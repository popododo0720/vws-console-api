package resource

import (
	"strings"
	"testing"
)

// AttachVolume takes only the device names the EC2 User Guide lists as
// available, and refuses the rest as EC2 does, with InvalidParameterValue
// naming the device (#400). /dev/sdaa and /dev/xvdpa are names EC2 is
// reported to refuse; /dev/xvdba is one it takes.
func TestAttachVolumeDeviceFollowsTheEC2Names(t *testing.T) {
	vol, err := Parse[VolumeID]("vol-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := Parse[InstanceID]("i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range []string{
		"/dev/sda", "/dev/sdf", "/dev/sdz", "/dev/sda1", "/dev/sdf9", "/dev/sdp15", "/dev/sda2",
		"/dev/hda", "/dev/hdz", "/dev/hdc10",
		"/dev/xvda", "/dev/xvdz", "/dev/xvdaa", "/dev/xvdba", "/dev/xvdcz", "/dev/xvdda", "/dev/xvddx",
		"xvdf", "xvdz", "xvdba", "xvddx",
	} {
		if _, err := (AttachVolumeRequest{VolumeID: vol, InstanceID: inst, Device: device}).Normalize(); err != nil {
			t.Errorf("%q: %v, want accepted", device, err)
		}
	}
	for _, device := range []string{
		"/dev/sdaa", "/dev/xvdpa", "/dev/xvdda1", "/dev/xvddy", "/dev/xvdea", "/dev/xvdzz", "/dev/xvdaaa",
		"/dev/sda0", "/dev/sda16", "/dev/sda01", "/dev/sda100", "/dev/sdA", "/dev/SDF", "/dev/sd",
		"/dev/xvd", "/dev/xvdf1", "/dev/nvme1n1", "/dev/vdb", "sdf", "dev/sdf", "/dev//sdf",
		"/dev/sd f", "/dev/sdf ", " /dev/sdf", "/dev/sdf\n", "/dev/sdf\x00", "/dev/sdf/../sdg", "/dev/sdé",
		"xvdf1", "/sdf", "boot", "/dev/" + strings.Repeat("x", 29),
	} {
		_, err := (AttachVolumeRequest{VolumeID: vol, InstanceID: inst, Device: device}).Normalize()
		want := "Value (" + device + ") for parameter device is invalid. " + device + " is not a valid EBS device name."
		if e := AsError(err); e == nil || e.Code != CodeInvalidArgument || e.Field != "device" || e.Message != want {
			t.Errorf("%q: %v, want InvalidArgument on device with %q", device, err, want)
		}
	}
}
