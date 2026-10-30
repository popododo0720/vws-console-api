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
	for _, typ := range []VolumeType{VolumeIO1, VolumeIO2, VolumeST1, VolumeSC1, "GP3", "ssd", "io3"} {
		req := base
		req.RootVolumeType = typ
		_, err := req.Normalize()
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeInvalidArgument || e.Field != "volumeType" {
			t.Fatalf("%q: %v, want an invalid volumeType", typ, err)
		}
	}
}
