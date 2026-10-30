package ec2query

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// TestAttachTimeIsWhenTheAttachmentInitiated pins #298: EC2 attachTime is
// "the time stamp when the attachment initiated"
// (https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_VolumeAttachment.html,
// API_EbsInstanceBlockDevice.html, API_AttachVolume.html). The volume is
// created and the instance launched before the attach, so neither creation
// nor launch time can pass for it.
func TestAttachTimeIsWhenTheAttachmentInitiated(t *testing.T) {
	start := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	var offset atomic.Int64
	clock := func() time.Time { return start.Add(time.Duration(offset.Load())) }
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{Now: clock}).Set()})
	static := iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account)
	h := New(Config{Service: svc, Authorizer: static, Verifier: sigv4.NewVerifier(sigv4.Verifier{
		Service: sigv4.ServiceEC2, Region: resource.RegionName, Now: clock, Auth: iam.Authenticator(static),
	})})
	send := func(f url.Values) string {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, clock(), f.Encode())
		if res.Code != http.StatusOK {
			t.Fatalf("%s %d %s", f.Get("Action"), res.Code, res.Body)
		}
		return res.Body.String()
	}
	vpc := send(url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.6.0.0/16"}})
	subnet := send(url.Values{
		"Action": {"CreateSubnet"}, "VpcId": {xmlText(t, vpc, "vpcId")}, "CidrBlock": {"10.6.1.0/24"},
	})
	inst := xmlText(t, send(url.Values{
		"Action": {"RunInstances"}, "ImageId": {"ami-0123456789abcdef0"}, "InstanceType": {"vws.small"},
		"SubnetId": {xmlText(t, subnet, "subnetId")}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {"run-298"},
	}), "instanceId")
	offset.Add(int64(time.Minute))
	vol := xmlText(t, send(url.Values{
		"Action": {"CreateVolume"}, "AvailabilityZone": {"vws-1a"}, "Size": {"1"}, "ClientToken": {"vol-298"},
	}), "volumeId")
	offset.Add(int64(time.Minute))
	launched, attached := "2026-10-09T10:00:00.000Z", "2026-10-09T10:02:00.000Z"

	body := send(url.Values{"Action": {"AttachVolume"}, "VolumeId": {vol}, "InstanceId": {inst}, "Device": {"/dev/sdf"}})
	if got := xmlText(t, body, "attachTime"); got != attached {
		t.Fatalf("AttachVolume attachTime %s, want %s", got, attached)
	}
	offset.Add(int64(time.Minute))

	var volumes struct {
		Items []struct {
			ID          string `xml:"volumeId"`
			Created     string `xml:"createTime"`
			Attachments []struct {
				AttachTime string `xml:"attachTime"`
			} `xml:"attachmentSet>item"`
		} `xml:"volumeSet>item"`
	}
	described := send(url.Values{"Action": {"DescribeVolumes"}, "VolumeId.1": {vol}})
	if err := xml.Unmarshal([]byte(described), &volumes); err != nil {
		t.Fatal(err)
	}
	if len(volumes.Items) != 1 || len(volumes.Items[0].Attachments) != 1 ||
		volumes.Items[0].Attachments[0].AttachTime != attached || volumes.Items[0].Created == attached {
		t.Fatalf("DescribeVolumes %+v, want attachTime %s apart from createTime", volumes.Items, attached)
	}

	var instances struct {
		Blocks []struct {
			Device     string `xml:"deviceName"`
			AttachTime string `xml:"ebs>attachTime"`
		} `xml:"reservationSet>item>instancesSet>item>blockDeviceMapping>item"`
	}
	listed := send(url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {inst}})
	if err := xml.Unmarshal([]byte(listed), &instances); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{resource.RootDeviceName: launched, "/dev/sdf": attached}
	if len(instances.Blocks) != len(want) {
		t.Fatalf("blockDeviceMapping %+v, want %v", instances.Blocks, want)
	}
	for _, b := range instances.Blocks {
		if want[b.Device] != b.AttachTime {
			t.Fatalf("blockDeviceMapping %s attachTime %s, want %s", b.Device, b.AttachTime, want[b.Device])
		}
	}

	detached := send(url.Values{"Action": {"DetachVolume"}, "VolumeId": {vol}})
	if got := xmlText(t, detached, "attachTime"); got != attached {
		t.Fatalf("DetachVolume attachTime %s, want %s", got, attached)
	}
}

// TestAttachTimeStandsInWhenTheBackendRecordsNone pins what a backend that
// records no attach time shows (gRPC until vws-proto#83): the volume's
// creation time, the instance's launch time, and the accept time on
// AttachVolume, the earliest the attachment can have initiated.
func TestAttachTimeStandsInWhenTheBackendRecordsNone(t *testing.T) {
	vol, err := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := resource.Parse[resource.InstanceID]("i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 10, 9, 10, 1, 0, 0, time.UTC)
	launched := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	item := volumeXML(resource.Volume{
		ID: vol, State: resource.VolumeInUse, InstanceID: inst, Device: "/dev/sdf", CreateTime: created,
	})
	if got := item.Attachments.Items[0].AttachTime; got != "2026-10-09T10:01:00.000Z" {
		t.Fatalf("volume attachTime %s, want the creation time", got)
	}
	set := blockSetOf(resource.Instance{
		LaunchTime: launched, BlockDevices: []resource.BlockDevice{{Device: "/dev/sdf", VolumeID: vol}},
	})
	if got := set.Items[0].EBS.AttachTime; got != "2026-10-09T10:00:00.000Z" {
		t.Fatalf("block attachTime %s, want the launch time", got)
	}
	recorded := time.Date(2026, 10, 9, 10, 2, 0, 0, time.UTC)
	if got := attachTimeOr(recorded, launched); !got.Equal(recorded) {
		t.Fatalf("a recorded attach time %s lost to the stand-in: %s", recorded, got)
	}
}
