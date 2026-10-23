package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestAttachVolumeAnswersAttaching pins #214 on the wire. EC2 answers an
// accepted AttachVolume with status attaching
// (https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AttachVolume.html),
// and DescribeVolumes shows the volume in-use with its attachment. The fake
// here settles at once, so the attachment already reads attached.
func TestAttachVolumeAnswersAttaching(t *testing.T) {
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
	vpc := send(url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.5.0.0/16"}})
	subnet := send(url.Values{
		"Action": {"CreateSubnet"}, "VpcId": {xmlText(t, vpc, "vpcId")}, "CidrBlock": {"10.5.1.0/24"},
	})
	run := send(url.Values{
		"Action": {"RunInstances"}, "ImageId": {"ami-0123456789abcdef0"}, "InstanceType": {"vws.small"},
		"SubnetId": {xmlText(t, subnet, "subnetId")}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {"run-214"},
	})
	inst := xmlText(t, run, "instanceId")
	vol := xmlText(t, send(url.Values{
		"Action": {"CreateVolume"}, "AvailabilityZone": {"vws-1a"}, "Size": {"1"}, "ClientToken": {"vol-214"},
	}), "volumeId")
	body := send(url.Values{"Action": {"AttachVolume"}, "VolumeId": {vol}, "InstanceId": {inst}, "Device": {"/dev/sdf"}})
	for _, want := range []string{
		"<volumeId>" + vol + "</volumeId>", "<instanceId>" + inst + "</instanceId>",
		"<device>/dev/sdf</device>", "<status>attaching</status>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("AttachVolume: no %s in %s", want, body)
		}
	}
	taken := signed(t, h, cred, now, url.Values{
		"Action": {"AttachVolume"}, "Version": {Version}, "VolumeId": {vol},
		"InstanceId": {inst}, "Device": {"/dev/sdg"}, "ClientToken": {"attach-taken"},
	}.Encode())
	if got := ec2ErrorXML(t, taken.Body.Bytes()); taken.Code != http.StatusBadRequest ||
		got.Code != "IncorrectState" || got.Message != vol+" is not 'available'." {
		t.Fatalf("attach a taken volume %d %+v", taken.Code, got)
	}
	described := send(url.Values{"Action": {"DescribeVolumes"}, "VolumeId.1": {vol}})
	for _, want := range []string{
		"<status>in-use</status>", "<instanceId>" + inst + "</instanceId>",
		"<device>/dev/sdf</device>", "<status>attached</status>",
	} {
		if !strings.Contains(described, want) {
			t.Fatalf("DescribeVolumes: no %s in %s", want, described)
		}
	}
}

// TestVolumeAttachmentStatus pins the attachmentSet status for each backend
// attachment state. The volume state is in-use for all of them.
func TestVolumeAttachmentStatus(t *testing.T) {
	inst, err := resource.Parse[resource.InstanceID]("i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	vol, err := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name  string
		state resource.AttachmentStatus
		want  string
	}{
		{name: "attaching", state: resource.AttachmentAttaching, want: "attaching"},
		{name: "attached", state: resource.AttachmentAttached, want: "attached"},
		{name: "a backend that sets no state", state: "", want: "attached"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			item := volumeXML(resource.Volume{
				ID: vol, State: resource.VolumeInUse, InstanceID: inst, Device: "/dev/sdf", AttachState: row.state,
			})
			if item.Status != "in-use" || len(item.Attachments.Items) != 1 {
				t.Fatalf("item %+v", item)
			}
			if got := item.Attachments.Items[0]; got.Status != row.want || got.InstanceID != inst.String() {
				t.Fatalf("attachment %+v, want status %s", got, row.want)
			}
		})
	}
	if item := volumeXML(resource.Volume{ID: vol, State: resource.VolumeAvailable}); len(item.Attachments.Items) != 0 {
		t.Fatalf("detached volume has attachments %+v", item.Attachments.Items)
	}
}
