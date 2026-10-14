package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// attachTimeOK checks an attachTime is present and in EC2's ISO 8601 UTC form.
func attachTimeOK(t *testing.T, body string) {
	t.Helper()
	got := xmlText(t, body, "attachTime")
	if _, err := time.Parse("2006-01-02T15:04:05.000Z", got); err != nil {
		t.Fatalf("attachTime %q: %v in %s", got, err, body)
	}
}

// #127: DescribeInstances names the root device and its EBS volume, and
// DescribeVolumes lists that volume attached.
func TestRootDeviceAndVolume(t *testing.T) {
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
	vpc := send(url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}})
	subnet := send(url.Values{"Action": {"CreateSubnet"}, "VpcId": {xmlText(t, vpc, "vpcId")}, "CidrBlock": {"10.0.1.0/24"}})
	run := send(url.Values{
		"Action": {"RunInstances"}, "ImageId": {"ami-0123456789abcdef0"}, "InstanceType": {"vws.small"},
		"SubnetId": {xmlText(t, subnet, "subnetId")}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {"run-root"},
	})
	id := xmlText(t, run, "instanceId")
	got := send(url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {id}})
	for _, want := range []string{
		"<rootDeviceName>/dev/xvda</rootDeviceName>", "<rootDeviceType>ebs</rootDeviceType>",
		"<blockDeviceMapping><item><deviceName>/dev/xvda</deviceName><ebs><volumeId>vol-",
		"<status>attached</status>", "<deleteOnTermination>true</deleteOnTermination>",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("no %s in %s", want, got)
		}
	}
	_, mapping, _ := strings.Cut(got, "<blockDeviceMapping>")
	attachTimeOK(t, mapping)
	vol := xmlText(t, mapping, "volumeId")
	vols := send(url.Values{"Action": {"DescribeVolumes"}, "VolumeId.1": {vol}})
	for _, want := range []string{"<instanceId>" + id + "</instanceId>", "<device>/dev/xvda</device>", "<status>in-use</status>", "<deleteOnTermination>true</deleteOnTermination>"} {
		if !strings.Contains(vols, want) {
			t.Fatalf("no %s in %s", want, vols)
		}
	}
	_, att, _ := strings.Cut(vols, "<attachmentSet>")
	attachTimeOK(t, att)
}
