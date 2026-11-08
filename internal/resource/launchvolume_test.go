package resource

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func launchBase(t *testing.T) RunInstancesRequest {
	t.Helper()
	img, err := Parse[ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	sub, err := Parse[SubnetID]("subnet-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	return RunInstancesRequest{ImageID: img, InstanceType: "vws.small", SubnetID: sub}
}

// extras is n gp2 volumes of 1 GiB at /dev/xvdaa onward.
func extras(n int) []LaunchVolume {
	out := make([]LaunchVolume, 0, n)
	for i := range n {
		out = append(out, LaunchVolume{Device: "/dev/xvd" + string(rune('a'+i/26)) + string(rune('a'+i%26)), SizeGiB: 1})
	}
	return out
}

// #423 AC2: a non-root mapping takes the CreateVolume type, size and
// performance rules on its own type, st1 and sc1 included, with gp2 and the
// gp3 defaults when omitted.
func TestExtraVolumeShape(t *testing.T) {
	for _, v := range []LaunchVolume{
		{Device: "/dev/sdf", SizeGiB: 1},
		{Device: "/dev/sdf", SizeGiB: 125, Type: VolumeST1},
		{Device: "/dev/sdf", SizeGiB: 16384, Type: VolumeSC1},
		{Device: "/dev/sdf", SizeGiB: 1024, Type: VolumeStandard},
		{Device: "/dev/sdf", SizeGiB: 20, Type: VolumeGP3, Iops: 4000, Throughput: 250},
		{Device: "/dev/sdf", SizeGiB: 20, Type: VolumeIO1, Iops: 1000},
		{Device: "/dev/sdf", SizeGiB: 4, Type: VolumeIO2, Iops: 100},
	} {
		req := launchBase(t)
		req.ExtraVolumes = []LaunchVolume{v}
		if _, err := req.Normalize(); err != nil {
			t.Fatalf("%+v: %v", v, err)
		}
	}
	for typ, want := range map[VolumeType][3]int64{
		"": {0, 0}, VolumeGP3: {3000, 125}, VolumeIO1: {400, 0}, VolumeST1: {0, 0},
	} {
		v := LaunchVolume{Type: typ}
		if typ == VolumeIO1 {
			v.Iops = 400
		}
		if iops, miBps := v.Performance(); iops != want[0] || miBps != want[1] {
			t.Fatalf("%q: %d IOPS %d MiB/s, want %v", typ, iops, miBps, want)
		}
	}
	if got := (LaunchVolume{}).VolumeType(); got != VolumeGP2 {
		t.Fatalf("omitted type is %q, want gp2", got)
	}
}

// #423 AC2: every non-root mapping is checked in Normalize, so both surfaces
// refuse the same requests before the backend, each with the EC2 refinement
// of its code.
func TestExtraVolumesAreChecked(t *testing.T) {
	type want struct {
		field, message string
		is             func(*Error) bool
	}
	plain := func(*Error) bool { return true }
	for _, c := range []struct {
		name   string
		extras []LaunchVolume
		want   want
	}{
		{"27 volumes with the root", extras(MaxLaunchVolumes), want{
			"blockDeviceMapping", "a VWS instance takes 27, the root volume included", IsAttachmentLimitExceeded,
		}},
		{"limit before a bad entry", append(extras(MaxLaunchVolumes-1), LaunchVolume{Device: "/dev/foo"}), want{
			"blockDeviceMapping", "a VWS instance takes 27", IsAttachmentLimitExceeded,
		}},
		{"not an EBS device name", []LaunchVolume{{Device: "/dev/xvddy", SizeGiB: 1}}, want{
			"blockDeviceMapping", "/dev/xvddy is not a valid EBS device name.", plain,
		}},
		{"no device name", []LaunchVolume{{SizeGiB: 1}}, want{
			"blockDeviceMapping", " is not a valid EBS device name.", plain,
		}},
		{"the root device", []LaunchVolume{{Device: RootDeviceName, SizeGiB: 1}}, want{
			"blockDeviceMapping", "device /dev/xvda is mapped more than once", plain,
		}},
		{"the root device without /dev/", []LaunchVolume{{Device: "xvda", SizeGiB: 1}}, want{
			"blockDeviceMapping", "device xvda is mapped more than once", plain,
		}},
		{"a device twice", []LaunchVolume{{Device: "/dev/sdf", SizeGiB: 1}, {Device: "/dev/sdf", SizeGiB: 2}}, want{
			"blockDeviceMapping", "device /dev/sdf is mapped more than once", plain,
		}},
		{"a device twice, once without /dev/", []LaunchVolume{
			{Device: "/dev/xvdf", SizeGiB: 1}, {Device: "xvdf", SizeGiB: 1},
		}, want{"blockDeviceMapping", "device xvdf is mapped more than once", plain}},
		{"no size", []LaunchVolume{{Device: "/dev/sdf", Type: VolumeGP3}}, want{
			"blockDeviceMapping", "/dev/sdf: you must specify either a snapshot ID or a volume size", plain,
		}},
		{"negative size", []LaunchVolume{{Device: "/dev/sdf", SizeGiB: -1}}, want{
			"size", "Value (-1) for parameter size is invalid.", plain,
		}},
		{"negative iops", []LaunchVolume{{Device: "/dev/sdf", SizeGiB: 8, Iops: -1}}, want{
			"iops", "Value (-1) for parameter iops is invalid.", plain,
		}},
		{"negative throughput", []LaunchVolume{{Device: "/dev/sdf", SizeGiB: 8, Throughput: -1}}, want{
			"throughput", "Value (-1) for parameter throughput is invalid.", plain,
		}},
		{"unknown type", []LaunchVolume{{Device: "/dev/sdf", SizeGiB: 8, Type: "io3"}}, want{
			"volumeType", "unsupported", plain,
		}},
		{"st1 below 125 GiB", []LaunchVolume{{Device: "/dev/sdf", SizeGiB: 124, Type: VolumeST1}}, want{
			"size", "Volume of 124GiB is too small; minimum is 125GiB.", plain,
		}},
		{"io1 without iops", []LaunchVolume{{Device: "/dev/sdf", SizeGiB: 8, Type: VolumeIO1}}, want{
			"iops", "The parameter iops must be specified for io1 volumes.", IsMissingParameter,
		}},
		{"io1 ratio", []LaunchVolume{{Device: "/dev/sdf", SizeGiB: 19, Type: VolumeIO1, Iops: 1000}}, want{
			"iops", "Iops to volume size ratio", plain,
		}},
		{"gp2 iops", []LaunchVolume{{Device: "/dev/sdf", SizeGiB: 8, Iops: 3000}}, want{
			"iops", "The parameter iops is not supported for gp2 volumes.", IsInvalidCombination,
		}},
	} {
		req := launchBase(t)
		req.ExtraVolumes = c.extras
		_, err := req.Normalize()
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeInvalidArgument || e.Field != c.want.field ||
			!strings.Contains(e.Message, c.want.message) || !c.want.is(e) {
			t.Fatalf("%s: %v, want %s %q", c.name, err, c.want.field, c.want.message)
		}
		if c.want.field != "blockDeviceMapping" && IsAttachmentLimitExceeded(e) {
			t.Fatalf("%s: %v is AttachmentLimitExceeded", c.name, err)
		}
	}
	// 26 volumes and the root are the most an instance takes, and EC2
	// spells an xvd device with or without /dev/.
	req := launchBase(t)
	req.ExtraVolumes = extras(MaxLaunchVolumes - 1)
	req.ExtraVolumes[0].Device = "xvdaa"
	if _, err := req.Normalize(); err != nil {
		t.Fatalf("26 extra volumes: %v", err)
	}
}

// Normalize writes nothing into the caller's volumes, so a request it
// refuses or takes leaves them as sent.
func TestNormalizeLeavesTheCallersVolumes(t *testing.T) {
	req := launchBase(t)
	req.ExtraVolumes = []LaunchVolume{{Device: "/dev/sdf", SizeGiB: 8}}
	got, err := req.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if got.ExtraVolumes[0] != (LaunchVolume{Device: "/dev/sdf", SizeGiB: 8}) ||
		req.ExtraVolumes[0] != got.ExtraVolumes[0] {
		t.Fatalf("normalized %+v from %+v", got.ExtraVolumes, req.ExtraVolumes)
	}
}

// A request without extra volumes, nil or empty, marshals as it did before
// #423 AC2, so its idempotency fingerprint does not change; one with them is
// another fingerprint for every field of a mapping.
func TestRequestWithoutExtraVolumesKeepsItsFingerprint(t *testing.T) {
	req := launchBase(t)
	const legacy = `{"imageId":"ami-0123456789abcdef0","instanceType":"vws.small",` +
		`"subnetId":"subnet-0123456789abcdef0","count":0}`
	for _, v := range [][]LaunchVolume{nil, {}} {
		req.ExtraVolumes = v
		b, err := json.Marshal(req)
		if err != nil || string(b) != legacy {
			t.Fatalf("%v: %s %v", v, b, err)
		}
	}
	seen := map[string]bool{}
	for i, v := range []LaunchVolume{
		{Device: "/dev/sdf", SizeGiB: 8},
		{Device: "/dev/sdg", SizeGiB: 8},
		{Device: "/dev/sdf", SizeGiB: 9},
		{Device: "/dev/sdf", SizeGiB: 8, Type: VolumeGP3},
		{Device: "/dev/sdf", SizeGiB: 8, Type: VolumeGP3, Iops: 4000},
		{Device: "/dev/sdf", SizeGiB: 8, Type: VolumeGP3, Throughput: 200},
		{Device: "/dev/sdf", SizeGiB: 8, Kept: true},
	} {
		req.ExtraVolumes = []LaunchVolume{v}
		b, err := json.Marshal(req)
		if err != nil || seen[string(b)] || string(b) == legacy {
			t.Fatalf("mapping %d marshals to %s %v, not its own", i, b, err)
		}
		seen[string(b)] = true
	}
}
