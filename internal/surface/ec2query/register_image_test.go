package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// registerRecipe is what `aws ec2 register-image` sends for an image from a
// snapshot with --architecture, --virtualization-type, --ena-support and
// --root-device-name.
func registerRecipe(snapshot string) url.Values {
	return url.Values{
		"Action": {"RegisterImage"}, "Version": {Version}, "Name": {"web base"}, "Description": {"nightly"},
		"Architecture": {"x86_64"}, "VirtualizationType": {"hvm"}, "EnaSupport": {"true"},
		"RootDeviceName":                  {"/dev/xvda"},
		"BlockDeviceMapping.1.DeviceName": {"/dev/xvda"}, "BlockDeviceMapping.1.Ebs.SnapshotId": {snapshot},
		"BlockDeviceMapping.1.Ebs.DeleteOnTermination": {"true"},
	}
}

func snapshotToRegister(t *testing.T) (func(url.Values) (int, string), string) {
	t.Helper()
	h, cred, now := harness(t)
	call := func(form url.Values) (int, string) {
		res := signed(t, h, cred, now, form.Encode())
		return res.Code, res.Body.String()
	}
	code, body := call(url.Values{
		"Action": {"CreateVolume"}, "Version": {Version}, "Size": {"9"}, "AvailabilityZone": {resource.ZoneName},
	})
	if code != http.StatusOK {
		t.Fatalf("volume %d %s", code, body)
	}
	code, body = call(url.Values{
		"Action": {"CreateSnapshot"}, "Version": {Version}, "VolumeId": {xmlText(t, body, "volumeId")},
	})
	if code != http.StatusOK {
		t.Fatalf("snapshot %d %s", code, body)
	}
	return call, xmlText(t, body, "snapshotId")
}

func TestRegisterImageFromASnapshot(t *testing.T) {
	call, snapshot := snapshotToRegister(t)
	form := registerRecipe(snapshot)
	form.Set("ClientToken", "register-web-1")
	code, body := call(form)
	if code != http.StatusOK || !strings.Contains(body, "<RegisterImageResponse") {
		t.Fatalf("register %d %s", code, body)
	}
	image := xmlText(t, body, "imageId")
	if !strings.HasPrefix(image, "ami-") {
		t.Fatalf("image id %q", image)
	}
	code, body = call(url.Values{"Action": {"DescribeImages"}, "Version": {Version}, "ImageId.1": {image}})
	if code != http.StatusOK || xmlText(t, body, "name") != "web base" || xmlText(t, body, "description") != "nightly" ||
		xmlText(t, body, "imageState") != "available" {
		t.Fatalf("describe %d %s", code, body)
	}
	code, body = call(form)
	if code != http.StatusOK || xmlText(t, body, "imageId") != image {
		t.Fatalf("retry %d %s", code, body)
	}
}

func TestRegisterImageRefusals(t *testing.T) {
	call, snapshot := snapshotToRegister(t)
	for _, tc := range []struct {
		name, key, value, code, says string
	}{
		{"no name", "Name", "", "MissingParameter", "parameter Name"},
		{
			"no snapshot", "BlockDeviceMapping.1.Ebs.SnapshotId", "", "MissingParameter",
			"parameter BlockDeviceMapping.1.Ebs.SnapshotId",
		},
		{
			"no device", "BlockDeviceMapping.1.DeviceName", "", "MissingParameter",
			"parameter BlockDeviceMapping.1.DeviceName",
		},
		{"arm64", "Architecture", "arm64", "UnsupportedOperation", "Architecture arm64"},
		{"paravirtual", "VirtualizationType", "paravirtual", "UnsupportedOperation", "VirtualizationType paravirtual"},
		{"no ena", "EnaSupport", "false", "UnsupportedOperation", "EnaSupport false"},
		{"bad ena", "EnaSupport", "maybe", "InvalidParameterValue", "maybe"},
		{"kept root", "BlockDeviceMapping.1.Ebs.DeleteOnTermination", "false", "UnsupportedOperation", "DeleteOnTermination"},
		{"other device", "BlockDeviceMapping.1.DeviceName", "/dev/sdf", "UnsupportedOperation", "/dev/sdf"},
		{"root not mapped", "RootDeviceName", "/dev/sda1", "InvalidBlockDeviceMapping", "/dev/sda1"},
		{"short name", "Name", "ab", "InvalidAMIName.Malformed", ": ab<"},
		{
			"unknown snapshot", "BlockDeviceMapping.1.Ebs.SnapshotId", "snap-0000000000000000a", "InvalidSnapshot.NotFound",
			"snap-0000000000000000a",
		},
		{"second mapping", "BlockDeviceMapping.2.Ebs.SnapshotId", snapshot, "InvalidParameterValue", "unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form := registerRecipe(snapshot)
			if tc.value == "" {
				form.Del(tc.key)
			} else {
				form.Set(tc.key, tc.value)
			}
			code, body := call(form)
			if code != http.StatusBadRequest || xmlText(t, body, "Code") != tc.code || !strings.Contains(body, tc.says) {
				t.Fatalf("%d %s", code, body)
			}
		})
	}
	code, body := call(url.Values{"Action": {"DescribeImages"}, "Version": {Version}, "Owner.1": {"self"}})
	if code != http.StatusOK || strings.Contains(body, "web base") {
		t.Fatalf("a refused request registered an image: %d %s", code, body)
	}
}

func TestPendingSnapshotIsIncorrectState(t *testing.T) {
	id, err := resource.Parse[resource.SnapshotID]("snap-0a1b2c3d4e5f60718")
	if err != nil {
		t.Fatal(err)
	}
	got := ec2Entry(resource.SnapshotNotCompleted(id))
	if got.HTTP != http.StatusBadRequest || got.Code != "IncorrectState" {
		t.Fatalf("pending snapshot answers %+v", got)
	}
}
