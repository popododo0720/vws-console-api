package resource

import (
	"errors"
	"testing"
)

// #323: the root volume type comes from the request, and an omitted type
// stays empty so that the fingerprint of an old request does not change.
func TestRunInstancesRootVolumeType(t *testing.T) {
	img, err := Parse[ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	sub, err := Parse[SubnetID]("subnet-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	base := RunInstancesRequest{ImageID: img, InstanceType: "vws.small", SubnetID: sub}
	for _, typ := range []VolumeType{"", VolumeStandard, VolumeGP2, VolumeGP3} {
		req := base
		req.RootVolumeType = typ
		got, err := req.Normalize()
		if err != nil {
			t.Fatalf("%q: %v", typ, err)
		}
		if got.RootVolumeType != typ {
			t.Fatalf("%q normalized to %q", typ, got.RootVolumeType)
		}
		want := typ
		if typ == "" {
			want = VolumeGP2
		}
		if got.RootType() != want {
			t.Fatalf("%q: root type %q, want %q", typ, got.RootType(), want)
		}
	}
	// A gp3 root volume gets the gp3 defaults, as CreateVolume gives (#418).
	for typ, want := range map[VolumeType][2]int64{"": {}, VolumeStandard: {}, VolumeGP2: {}, VolumeGP3: {3000, 125}} {
		iops, miBps := RunInstancesRequest{RootVolumeType: typ}.RootPerformance()
		if iops != want[0] || miBps != want[1] {
			t.Fatalf("%q: root performance %d IOPS %d MiB/s, want %v", typ, iops, miBps, want)
		}
	}
	// io1 and io2 need Ebs.Iops, which the mapping does not carry, so EC2
	// answers MissingParameter as CreateVolume does without Iops.
	for _, typ := range []VolumeType{VolumeIO1, VolumeIO2} {
		req := base
		req.RootVolumeType = typ
		_, err := req.Normalize()
		var e *Error
		if !errors.As(err, &e) || !IsMissingParameter(e) || e.Field != "iops" {
			t.Fatalf("%q: %v, want a missing iops", typ, err)
		}
	}
	for _, typ := range []VolumeType{VolumeST1, VolumeSC1, "GP3", "ssd", "io3"} {
		req := base
		req.RootVolumeType = typ
		_, err := req.Normalize()
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeInvalidArgument || e.Field != "volumeType" {
			t.Fatalf("%q: %v, want an invalid volumeType", typ, err)
		}
	}
}
