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
		gp3 := strings.Contains(vols, "<iops>3000</iops>") && strings.Contains(vols, "<throughput>125</throughput>")
		if gp3 != (want == "gp3") {
			t.Fatalf("root %s performance: %s", want, vols)
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
		{"io1 root needs Ebs.Iops", root("Ebs.VolumeType", "io1"), "MissingParameter"},
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
		{"root below the image", root("Ebs.VolumeSize", "7"), "InvalidBlockDeviceMapping"},
		{"zero size", root("Ebs.VolumeSize", "0"), "InvalidParameterValue"},
		{"size not a number", root("Ebs.VolumeSize", "big"), "InvalidParameterValue"},
		{"gp2 above 16 TiB", root("Ebs.VolumeSize", "16385"), "InvalidParameterValue"},
		{"standard above 1 TiB", url.Values{
			"BlockDeviceMapping.1.DeviceName": {"/dev/xvda"}, "BlockDeviceMapping.1.Ebs.VolumeType": {"standard"},
			"BlockDeviceMapping.1.Ebs.VolumeSize": {"1025"},
		}, "InvalidParameterValue"},
		// #429: the Iops-per-GiB ratio is checked on the mapping's size.
		{"io1 ratio on the mapping's size", url.Values{
			"BlockDeviceMapping.1.DeviceName": {"/dev/xvda"}, "BlockDeviceMapping.1.Ebs.VolumeType": {"io1"},
			"BlockDeviceMapping.1.Ebs.VolumeSize": {"19"}, "BlockDeviceMapping.1.Ebs.Iops": {"1000"},
		}, "InvalidParameterValue"},
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

// #423: the root mapping's Ebs.VolumeSize is the root volume size, within
// the per-type range, and DescribeVolumes reads it back.
func TestRunInstancesRootVolumeSizeRoundTrips(t *testing.T) {
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
	// #429: 1,000 io1 IOPS are above 50 per GiB at 8 GiB and within it at 20.
	for _, c := range []struct{ typ, size, iops string }{
		{"gp2", "8", ""}, {"gp3", "30", ""}, {"standard", "1024", ""}, {"io2", "65536", "3000"}, {"io1", "20", "1000"},
	} {
		extra := url.Values{
			"BlockDeviceMapping.1.DeviceName": {"/dev/xvda"}, "BlockDeviceMapping.1.Ebs.VolumeType": {c.typ},
			"BlockDeviceMapping.1.Ebs.VolumeSize": {c.size},
		}
		if c.iops != "" {
			extra.Set("BlockDeviceMapping.1.Ebs.Iops", c.iops)
		}
		run := send(launchForm(subnet, "root-size-"+c.typ, extra))
		got := send(url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {xmlText(t, run, "instanceId")}})
		_, mapping, _ := strings.Cut(got, "<blockDeviceMapping>")
		vols := send(url.Values{"Action": {"DescribeVolumes"}, "VolumeId.1": {xmlText(t, mapping, "volumeId")}})
		size := strings.Contains(vols, "<size>"+c.size+"</size>")
		if !size || !strings.Contains(vols, "<volumeType>"+c.typ+"</volumeType>") {
			t.Fatalf("%s root of %s GiB: %s", c.typ, c.size, vols)
		}
	}
}

// #423 AC4: a mapping field EC2 takes and VWS cannot honor is refused as
// UnsupportedOperation, naming the field and why, and creates nothing.
func TestUnsupportedBlockDeviceFieldsAreRefusedWithAReason(t *testing.T) {
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
		name, want string
		extra      url.Values
	}{
		{"root snapshot", "BlockDeviceMapping.1.Ebs.SnapshotId", root("Ebs.SnapshotId", "snap-0123456789abcdef0")},
		{"encrypted", "BlockDeviceMapping.1.Ebs.Encrypted", root("Ebs.Encrypted", "true")},
		{"kms key", "BlockDeviceMapping.1.Ebs.KmsKeyId", root("Ebs.KmsKeyId", "alias/aws/ebs")},
		{"no device", "BlockDeviceMapping.1.NoDevice", root("NoDevice", "")},
		{"instance store", "BlockDeviceMapping.1.VirtualName", url.Values{
			"BlockDeviceMapping.1.DeviceName": {"/dev/sdb"}, "BlockDeviceMapping.1.VirtualName": {"ephemeral0"},
		}},
		{"later mapping", "BlockDeviceMapping.2.Ebs.SnapshotId", url.Values{
			"BlockDeviceMapping.1.DeviceName": {"/dev/xvda"}, "BlockDeviceMapping.1.Ebs.VolumeType": {"gp3"},
			"BlockDeviceMapping.2.DeviceName": {"/dev/sdf"}, "BlockDeviceMapping.2.Ebs.SnapshotId": {"snap-0123456789abcdef0"},
		}},
	} {
		res := signed(t, h, cred, now, launchForm(subnet, "unsupported", c.extra).Encode())
		body := res.Body.String()
		if res.Code != http.StatusBadRequest || !strings.Contains(body, "<Code>UnsupportedOperation</Code>") ||
			!strings.Contains(body, c.want+" is not supported: ") {
			t.Fatalf("%s: %d %s", c.name, res.Code, body)
		}
	}
	if got := send(url.Values{"Action": {"DescribeInstances"}}); strings.Contains(got, "<instanceId>") {
		t.Fatalf("a refused launch created an instance: %s", got)
	}
	bad := signed(t, h, cred, now, launchForm(subnet, "bad-bool", root("Ebs.Encrypted", "yes")).Encode())
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "<Code>InvalidParameterValue</Code>") {
		t.Fatalf("Encrypted=yes: %d %s", bad.Code, bad.Body)
	}
	nameless := url.Values{"BlockDeviceMapping.1.Ebs.Encrypted": {"false"}}
	res := signed(t, h, cred, now, launchForm(subnet, "nameless", nameless).Encode())
	if res.Code != http.StatusBadRequest ||
		!strings.Contains(res.Body.String(), "<Code>InvalidBlockDeviceMapping</Code>") {
		t.Fatalf("Encrypted=false without DeviceName: %d %s", res.Code, res.Body)
	}
	// Encrypted=false states what every VWS volume is, so it launches.
	send(launchForm(subnet, "unencrypted", root("Ebs.Encrypted", "false")))
}
