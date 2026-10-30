package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// newSubnet creates a VPC and a subnet and returns the subnet id.
func newSubnet(t *testing.T, send func(url.Values) string) string {
	t.Helper()
	vpc := send(url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}})
	subnet := send(url.Values{
		"Action": {"CreateSubnet"}, "VpcId": {xmlText(t, vpc, "vpcId")}, "CidrBlock": {"10.0.1.0/24"},
	})
	return xmlText(t, subnet, "subnetId")
}

// launchForm is a RunInstances form in subnet. extra adds fields.
func launchForm(subnet, token string, extra url.Values) url.Values {
	f := url.Values{
		"Action": {"RunInstances"}, "Version": {Version}, "ImageId": {"ami-0123456789abcdef0"}, "InstanceType": {"vws.small"},
		"SubnetId": {subnet}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {token},
	}
	for k, v := range extra {
		f[k] = v
	}
	return f
}

// #323: BlockDeviceMapping.N.Ebs.VolumeType on the root device sets the
// root volume type, and DescribeVolumes reads it back.
func TestRunInstancesRootVolumeTypeRoundTrips(t *testing.T) {
	h, cred, now := harness(t)
	send := func(f url.Values) string {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		if res.Code != http.StatusOK {
			t.Fatalf("%s %d %s", f.Get("Action"), res.Code, res.Body)
		}
		return res.Body.String()
	}
	subnet := newSubnet(t, send)
	for _, want := range []string{"standard", "gp2", "gp3"} {
		run := send(launchForm(subnet, "root-"+want, url.Values{
			"BlockDeviceMapping.1.DeviceName":     {"/dev/xvda"},
			"BlockDeviceMapping.1.Ebs.VolumeType": {want},
		}))
		got := send(url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {xmlText(t, run, "instanceId")}})
		_, mapping, _ := strings.Cut(got, "<blockDeviceMapping>")
		vols := send(url.Values{"Action": {"DescribeVolumes"}, "VolumeId.1": {xmlText(t, mapping, "volumeId")}})
		if !strings.Contains(vols, "<volumeType>"+want+"</volumeType>") {
			t.Fatalf("root %s: %s", want, vols)
		}
	}
	// A mapping that names only the root device keeps the default.
	run := send(launchForm(subnet, "root-name-only", url.Values{"BlockDeviceMapping.1.DeviceName": {"/dev/xvda"}}))
	got := send(url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {xmlText(t, run, "instanceId")}})
	_, mapping, _ := strings.Cut(got, "<blockDeviceMapping>")
	vols := send(url.Values{"Action": {"DescribeVolumes"}, "VolumeId.1": {xmlText(t, mapping, "volumeId")}})
	if !strings.Contains(vols, "<volumeType>gp2</volumeType>") {
		t.Fatalf("root default: %s", vols)
	}
}

// #323: a root mapping VWS cannot honor is refused before anything is
// created, with the EC2 code for the reason.
func TestRunInstancesBlockDeviceMappingRefusals(t *testing.T) {
	h, cred, now := harness(t)
	send := func(f url.Values) string {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		if res.Code != http.StatusOK {
			t.Fatalf("%s %d %s", f.Get("Action"), res.Code, res.Body)
		}
		return res.Body.String()
	}
	subnet := newSubnet(t, send)
	root := func(field, value string) url.Values {
		return url.Values{"BlockDeviceMapping.1.DeviceName": {"/dev/xvda"}, "BlockDeviceMapping.1." + field: {value}}
	}
	for _, c := range []struct {
		name  string
		extra url.Values
		code  string
	}{
		{"io1 root needs Iops (#324)", root("Ebs.VolumeType", "io1"), "UnknownVolumeType"},
		{"st1 cannot boot", root("Ebs.VolumeType", "st1"), "UnknownVolumeType"},
		{"no such type", root("Ebs.VolumeType", "io3"), "UnknownVolumeType"},
		{"no device name", url.Values{"BlockDeviceMapping.1.Ebs.VolumeType": {"gp3"}}, "InvalidBlockDeviceMapping"},
		{"root mapped twice", url.Values{
			"BlockDeviceMapping.1.DeviceName": {"/dev/xvda"}, "BlockDeviceMapping.1.Ebs.VolumeType": {"gp3"},
			"BlockDeviceMapping.2.DeviceName": {"/dev/xvda"}, "BlockDeviceMapping.2.Ebs.VolumeType": {"gp2"},
		}, "InvalidBlockDeviceMapping"},
		{"extra volume is not supported", url.Values{
			"BlockDeviceMapping.1.DeviceName": {"/dev/sdf"}, "BlockDeviceMapping.1.Ebs.VolumeType": {"gp3"},
		}, "InvalidParameterValue"},
		{"volume size is not supported", root("Ebs.VolumeSize", "20"), "InvalidParameterValue"},
		{"index past the cap", url.Values{"BlockDeviceMapping.101.DeviceName": {"/dev/xvda"}}, "InvalidParameterValue"},
	} {
		f := launchForm(subnet, "refuse", c.extra)
		res := signed(t, h, cred, now, f.Encode())
		if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "<Code>"+c.code+"</Code>") {
			t.Fatalf("%s: %d %s", c.name, res.Code, res.Body)
		}
	}
	if got := send(url.Values{"Action": {"DescribeInstances"}}); strings.Contains(got, "<instanceId>") {
		t.Fatalf("a refused launch created an instance: %s", got)
	}
}

// #323: the root volume type is part of the request, so a retry with the
// same ClientToken and another type is IdempotentParameterMismatch.
func TestRunInstancesRootVolumeTypeIsFingerprinted(t *testing.T) {
	h, cred, now := harness(t)
	send := func(f url.Values) string {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		if res.Code != http.StatusOK {
			t.Fatalf("%s %d %s", f.Get("Action"), res.Code, res.Body)
		}
		return res.Body.String()
	}
	subnet := newSubnet(t, send)
	f := launchForm(subnet, "fp-root", url.Values{
		"BlockDeviceMapping.1.DeviceName": {"/dev/xvda"}, "BlockDeviceMapping.1.Ebs.VolumeType": {"gp3"},
	})
	first := xmlText(t, send(f), "instanceId")
	if again := xmlText(t, send(f), "instanceId"); again != first {
		t.Fatalf("replay launched %s, want %s", again, first)
	}
	f.Set("BlockDeviceMapping.1.Ebs.VolumeType", "standard")
	res := signed(t, h, cred, now, f.Encode())
	if res.Code != http.StatusBadRequest ||
		!strings.Contains(res.Body.String(), "<Code>IdempotentParameterMismatch</Code>") {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
}
