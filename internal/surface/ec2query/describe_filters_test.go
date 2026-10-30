package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

func callEC2(t *testing.T, h http.Handler, cred sigv4.Credential, now time.Time, form url.Values) string {
	t.Helper()
	form.Set("Version", Version)
	res := signed(t, h, cred, now, form.Encode())
	if res.Code != http.StatusOK {
		t.Fatalf("%s %d %s", form.Get("Action"), res.Code, res.Body)
	}
	return res.Body.String()
}

func createVpcAndSubnet(
	t *testing.T, h http.Handler, cred sigv4.Credential, now time.Time,
	vpcCidr, subnetCidr string, tags url.Values,
) (string, string) {
	t.Helper()
	vpcForm := url.Values{"Action": {"CreateVpc"}, "CidrBlock": {vpcCidr}}
	for key, values := range tags {
		vpcForm[key] = values
	}
	vpc := xmlText(t, callEC2(t, h, cred, now, vpcForm), "vpcId")
	subnet := subnetIDOf(t, callEC2(t, h, cred, now, url.Values{
		"Action": {"CreateSubnet"}, "VpcId": {vpc}, "CidrBlock": {subnetCidr},
	}))
	return vpc, subnet
}

func TestDescribeSubnetsFiltersByVpcID(t *testing.T) {
	h, cred, now := harness(t)
	vpcA, subnetA := createVpcAndSubnet(t, h, cred, now, "10.11.0.0/16", "10.11.1.0/24", nil)
	_, subnetB := createVpcAndSubnet(t, h, cred, now, "10.12.0.0/16", "10.12.1.0/24", nil)
	body := callEC2(t, h, cred, now, url.Values{
		"Action": {"DescribeSubnets"}, "Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {vpcA},
	})
	if !strings.Contains(body, subnetA) || strings.Contains(body, subnetB) {
		t.Fatalf("subnets %s and %s: %s", subnetA, subnetB, body)
	}
}

func TestDescribeSubnetsFilterPagesTheMatches(t *testing.T) {
	h, cred, now := harness(t)
	vpc, first := createVpcAndSubnet(t, h, cred, now, "10.13.0.0/16", "10.13.1.0/24", nil)
	second := subnetIDOf(t, callEC2(t, h, cred, now, url.Values{
		"Action": {"CreateSubnet"}, "VpcId": {vpc}, "CidrBlock": {"10.13.2.0/24"},
	}))
	_, other := createVpcAndSubnet(t, h, cred, now, "10.14.0.0/16", "10.14.1.0/24", nil)
	form := url.Values{
		"Action": {"DescribeSubnets"}, "Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {vpc},
		"MaxResults": {"1"},
	}
	body := callEC2(t, h, cred, now, form)
	firstPage := xmlText(t, body, "subnetId")
	if strings.Count(body, "<subnetId>") != 1 ||
		(firstPage != first && firstPage != second) || strings.Contains(body, other) {
		t.Fatalf("first page %s: %s", firstPage, body)
	}
	form.Set("NextToken", xmlText(t, body, "nextToken"))
	body = callEC2(t, h, cred, now, form)
	want := first
	if firstPage == first {
		want = second
	}
	if got := strings.Count(body, "<subnetId>"); got != 1 || !strings.Contains(body, want) {
		t.Fatalf("second page %s: %s", want, body)
	}
}

func TestDescribeVpcsFiltersByTagName(t *testing.T) {
	h, cred, now := harness(t)
	web, _ := createVpcAndSubnet(t, h, cred, now, "10.15.0.0/16", "10.15.1.0/24", url.Values{
		"TagSpecification.1.ResourceType": {"vpc"},
		"TagSpecification.1.Tag.1.Key":    {"Name"},
		"TagSpecification.1.Tag.1.Value":  {"web"},
	})
	_, _ = createVpcAndSubnet(t, h, cred, now, "10.16.0.0/16", "10.16.1.0/24", nil)
	body := callEC2(t, h, cred, now, url.Values{
		"Action": {"DescribeVpcs"}, "Filter.1.Name": {"tag:Name"}, "Filter.1.Value.1": {"web"},
	})
	if !strings.Contains(body, web) || strings.Count(body, "<vpcId>") != 1 {
		t.Fatalf("tag:Name web: %s", body)
	}
	body = callEC2(t, h, cred, now, url.Values{
		"Action": {"DescribeVpcs"}, "Filter.1.Name": {"tag:Name"}, "Filter.1.Value.1": {"w*"},
	})
	if !strings.Contains(body, web) || strings.Count(body, "<vpcId>") != 1 {
		t.Fatalf("tag:Name w*: %s", body)
	}
}

func TestDescribeVolumesFiltersByAttachmentInstanceID(t *testing.T) {
	h, cred, now := harness(t)
	_, subnet := createVpcAndSubnet(t, h, cred, now, "10.17.0.0/16", "10.17.1.0/24", nil)
	run := callEC2(t, h, cred, now, url.Values{
		"Action": {"RunInstances"}, "ImageId": {"ami-0123456789abcdef0"}, "InstanceType": {"vws.small"},
		"SubnetId": {subnet}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {"run-92"},
	})
	instance := xmlText(t, run, "instanceId")
	attached := xmlText(t, callEC2(t, h, cred, now, url.Values{
		"Action": {"CreateVolume"}, "AvailabilityZone": {"vws-1a"}, "Size": {"1"}, "ClientToken": {"vol-92-attached"},
	}), "volumeId")
	detached := xmlText(t, callEC2(t, h, cred, now, url.Values{
		"Action": {"CreateVolume"}, "AvailabilityZone": {"vws-1a"}, "Size": {"1"}, "ClientToken": {"vol-92-detached"},
	}), "volumeId")
	callEC2(t, h, cred, now, url.Values{
		"Action": {"AttachVolume"}, "VolumeId": {attached}, "InstanceId": {instance}, "Device": {"/dev/sdf"},
	})
	body := callEC2(t, h, cred, now, url.Values{
		"Action": {"DescribeVolumes"}, "Filter.1.Name": {"attachment.instance-id"}, "Filter.1.Value.1": {instance},
	})
	if !strings.Contains(body, attached) || strings.Contains(body, detached) {
		t.Fatalf("attached %s detached %s: %s", attached, detached, body)
	}
}

func TestDescribeInstancesFiltersByVpcID(t *testing.T) {
	h, cred, now := harness(t)
	vpcA, subnetA := createVpcAndSubnet(t, h, cred, now, "10.18.0.0/16", "10.18.1.0/24", nil)
	_, subnetB := createVpcAndSubnet(t, h, cred, now, "10.19.0.0/16", "10.19.1.0/24", nil)
	run := func(subnet, token string) string {
		t.Helper()
		return xmlText(t, callEC2(t, h, cred, now, url.Values{
			"Action": {"RunInstances"}, "ImageId": {"ami-0123456789abcdef0"}, "InstanceType": {"vws.small"},
			"SubnetId": {subnet}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {token},
		}), "instanceId")
	}
	inA, inB := run(subnetA, "run-92-a"), run(subnetB, "run-92-b")
	body := callEC2(t, h, cred, now, url.Values{
		"Action": {"DescribeInstances"}, "Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {vpcA},
	})
	if !strings.Contains(body, inA) || strings.Contains(body, inB) {
		t.Fatalf("instances %s and %s: %s", inA, inB, body)
	}
}
