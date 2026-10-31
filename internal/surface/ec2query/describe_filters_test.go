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

// wantNextTokenMessage is the sentence AWS returns with InvalidNextToken.
const wantNextTokenMessage = "The specified next token is not valid."

func TestFilteredDescribesRejectAStaleNextToken(t *testing.T) {
	h, cred, now := harness(t)
	vpc, first := createVpcAndSubnet(t, h, cred, now, "10.20.0.0/16", "10.20.1.0/24", nil)
	second := subnetIDOf(t, callEC2(t, h, cred, now, url.Values{
		"Action": {"CreateSubnet"}, "VpcId": {vpc}, "CidrBlock": {"10.20.2.0/24"},
	}))
	if first == second {
		t.Fatalf("subnets share the id %s", first)
	}
	form := url.Values{
		"Action": {"DescribeSubnets"}, "Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {vpc},
		"MaxResults": {"1"},
	}
	firstPage := callEC2(t, h, cred, now, form)
	token := xmlText(t, firstPage, "nextToken")
	if token == "" {
		t.Fatalf("one-row page has no next token: %s", firstPage)
	}
	form.Set("Filter.1.Value.1", "vpc-00000000000000000")
	form.Set("NextToken", token)
	res := signed(t, h, cred, now, form.Encode())
	if res.Code != http.StatusBadRequest {
		t.Fatalf("stale token: %d %s", res.Code, res.Body)
	}
	body := ec2ErrorXML(t, res.Body.Bytes())
	if body.Code != "InvalidNextToken" || body.Message != wantNextTokenMessage {
		t.Fatalf("stale token: code %q message %q", body.Code, body.Message)
	}
}

func TestFilteredDescribesRejectAnUnknownNextToken(t *testing.T) {
	h, cred, now := harness(t)
	cases := []struct {
		action, name, value string
	}{
		{"DescribeVpcs", "tag:Name", "absent"},
		{"DescribeVolumes", "attachment.instance-id", "i-00000000000000000"},
		{"DescribeInstances", "vpc-id", "vpc-00000000000000000"},
		{"DescribeSubnets", "vpc-id", "vpc-00000000000000000"},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			form := url.Values{
				"Action": {tc.action}, "Version": {Version}, "NextToken": {"stale"},
				"Filter.1.Name": {tc.name}, "Filter.1.Value.1": {tc.value},
			}
			res := signed(t, h, cred, now, form.Encode())
			if res.Code != http.StatusBadRequest {
				t.Fatalf("%s: %d %s", tc.action, res.Code, res.Body)
			}
			body := ec2ErrorXML(t, res.Body.Bytes())
			if body.Code != "InvalidNextToken" || body.Message != wantNextTokenMessage {
				t.Fatalf("%s: code %q message %q", tc.action, body.Code, body.Message)
			}
		})
	}
}

func TestFilterWithNoValuesMatchesNothing(t *testing.T) {
	h, cred, now := harness(t)
	vpc := xmlText(t, callEC2(t, h, cred, now, url.Values{
		"Action": {"CreateVpc"}, "CidrBlock": {"10.21.0.0/16"},
		"TagSpecification.1.ResourceType": {"vpc"},
		"TagSpecification.1.Tag.1.Key":    {"Name"},
		"TagSpecification.1.Tag.1.Value":  {"web"},
	}), "vpcId")
	all := callEC2(t, h, cred, now, url.Values{"Action": {"DescribeVpcs"}})
	if !strings.Contains(all, vpc) {
		t.Fatalf("created vpc %s missing from the unfiltered listing: %s", vpc, all)
	}
	empty := callEC2(t, h, cred, now, url.Values{
		"Action": {"DescribeVpcs"}, "Filter.1.Name": {"tag:Name"},
	})
	if strings.Contains(empty, "<vpcId>") {
		t.Fatalf("a filter with no values matched a vpc: %s", empty)
	}
	matched := callEC2(t, h, cred, now, url.Values{
		"Action": {"DescribeVpcs"}, "Filter.1.Name": {"tag:Name"}, "Filter.1.Value.1": {"web"},
	})
	if !strings.Contains(matched, vpc) {
		t.Fatalf("tag:Name=web missed vpc %s: %s", vpc, matched)
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

func TestDescribeInstancesFilterWithNoValuesMatchesNothing(t *testing.T) {
	h, cred, now := harness(t)
	_, subnet := createVpcAndSubnet(t, h, cred, now, "10.22.0.0/16", "10.22.1.0/24", nil)
	instance := xmlText(t, callEC2(t, h, cred, now, url.Values{
		"Action": {"RunInstances"}, "ImageId": {"ami-0123456789abcdef0"}, "InstanceType": {"vws.small"},
		"SubnetId": {subnet}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {"run-472-no-values"},
	}), "instanceId")
	for _, name := range []string{"instance-id", "instance-state-name"} {
		body := callEC2(t, h, cred, now, url.Values{
			"Action": {"DescribeInstances"}, "Filter.1.Name": {name},
		})
		if strings.Contains(body, "<instanceId>") {
			t.Fatalf("%s with no values matched an instance: %s", name, body)
		}
	}
	body := callEC2(t, h, cred, now, url.Values{
		"Action": {"DescribeInstances"}, "Filter.1.Name": {"instance-id"}, "Filter.1.Value.1": {instance},
	})
	if !strings.Contains(body, instance) {
		t.Fatalf("instance-id=%s missed the instance: %s", instance, body)
	}
}
