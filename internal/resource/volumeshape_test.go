package resource

import (
	"errors"
	"testing"
)

// #436: a volume whose stored size is already above its type's maximum has no
// target size at or above its own inside the range, so every explicit Size is
// refused, even the current size. EC2 ModifyVolume takes a target size at
// least the existing size, and a size change must stay within the limits of
// the current volume type (Amazon EBS User Guide, Modify an Amazon EBS volume
// using Elastic Volumes operations, Limitations).
func TestModifyRefusesSizeAboveTypeMaximum(t *testing.T) {
	// 2,048 GiB is reachable before #427: the old ModifyVolume cap was 16,384
	// GiB whatever the type.
	v := Volume{Type: VolumeStandard, SizeGiB: 2048}
	for _, tc := range []struct {
		size int64
		want string
	}{
		{2048, "Volume of 2048GiB is too large; maximum is 1024GiB."},
		{4096, "Volume of 4096GiB is too large; maximum is 1024GiB."},
		{1024, "a volume cannot shrink"},
	} {
		_, err := v.Modify(ModifyVolumeRequest{SizeGiB: tc.size})
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeInvalidArgument || e.Field != "size" || e.Message != tc.want {
			t.Errorf("grow %d GiB: %v, want InvalidArgument size %q", tc.size, err, tc.want)
		}
	}
	if v.SizeGiB != 2048 {
		t.Fatalf("a refused grow changed the volume to %d GiB", v.SizeGiB)
	}
}

// #324 AC1: ModifyVolume changes type, Iops and Throughput with the EC2
// rules (EC2 API Reference, ModifyVolume): a type change to gp3, io1 or io2
// defaults Iops to 3,000 and to gp3 Throughput to 125; a value left out keeps
// the stored one; the target type, size and performance are checked together.
func TestModifyChangesTypeAndPerformance(t *testing.T) {
	gp2 := Volume{Type: VolumeGP2, SizeGiB: 10}
	gp3 := Volume{Type: VolumeGP3, SizeGiB: 100, Iops: 4000, Throughput: 250}
	for _, tc := range []struct {
		name string
		v    Volume
		req  ModifyVolumeRequest
		want Volume
	}{
		{
			"gp2 to gp3 takes the defaults", gp2,
			ModifyVolumeRequest{Type: VolumeGP3},
			Volume{Type: VolumeGP3, SizeGiB: 10, Iops: 3000, Throughput: 125},
		},
		{
			"gp2 to st1 is legal with the grow in the same request", gp2,
			ModifyVolumeRequest{Type: VolumeST1, SizeGiB: 125},
			Volume{Type: VolumeST1, SizeGiB: 125},
		},
		{
			"gp2 to io2 with Iops", gp2,
			ModifyVolumeRequest{Type: VolumeIO2, Iops: 5000},
			Volume{Type: VolumeIO2, SizeGiB: 10, Iops: 5000},
		},
		{
			"gp3 Iops alone keeps Throughput", gp3,
			ModifyVolumeRequest{Iops: 6000},
			Volume{Type: VolumeGP3, SizeGiB: 100, Iops: 6000, Throughput: 250},
		},
		{
			"gp3 to io1 drops Throughput", gp3,
			ModifyVolumeRequest{Type: VolumeIO1},
			Volume{Type: VolumeIO1, SizeGiB: 100, Iops: 3000},
		},
		{
			"gp3 to gp2 drops both", gp3,
			ModifyVolumeRequest{Type: VolumeGP2},
			Volume{Type: VolumeGP2, SizeGiB: 100},
		},
		{
			"same type keeps performance", gp3,
			ModifyVolumeRequest{Type: VolumeGP3},
			gp3,
		},
		{
			"a size-only grow keeps unchecked stored performance",
			Volume{Type: VolumeGP3, SizeGiB: 8},
			ModifyVolumeRequest{SizeGiB: 9},
			Volume{Type: VolumeGP3, SizeGiB: 9},
		},
	} {
		got, err := tc.v.Modify(tc.req)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %+v, %v; want %+v", tc.name, got, err, tc.want)
		}
	}
}

// #324 AC1: a ModifyVolume target that breaks the EC2 per-type rules is
// refused with the EC2 code and message, and the volume is not changed.
func TestModifyRefusesAnIllegalTarget(t *testing.T) {
	gp2 := Volume{Type: VolumeGP2, SizeGiB: 10}
	gp3 := Volume{Type: VolumeGP3, SizeGiB: 100, Iops: 4000, Throughput: 250}
	for _, tc := range []struct {
		name    string
		v       Volume
		req     ModifyVolumeRequest
		combo   bool
		field   string
		message string
	}{
		{
			"st1 below its minimum size", gp2,
			ModifyVolumeRequest{Type: VolumeST1},
			false, "size", "Volume of 10GiB is too small; minimum is 125GiB.",
		},
		{
			"io1 default Iops over 50 per GiB", gp2,
			ModifyVolumeRequest{Type: VolumeIO1},
			false, "iops", "Iops to volume size ratio of 300.000000 is too high; maximum is 50.000000",
		},
		{
			"Iops on gp2", gp2,
			ModifyVolumeRequest{Iops: 3000},
			true, "iops", "The parameter iops is not supported for gp2 volumes.",
		},
		{
			"Throughput on io2", gp2,
			ModifyVolumeRequest{Type: VolumeIO2, Throughput: 500},
			true, "throughput", "The parameter throughput is not supported for io2 volumes.",
		},
		{
			"gp3 Iops below 3,000", gp3,
			ModifyVolumeRequest{Iops: 2000},
			false, "iops", "Volume iops of 2000 is too low; minimum is 3000.",
		},
		{
			"gp3 Throughput over 0.25 per IOPS", gp3,
			ModifyVolumeRequest{Throughput: 1001},
			false, "throughput", "Throughput (MiBps) to iops ratio of 0.250250 is too high; maximum is 0.250000 MiBps per iops.",
		},
		{
			"a shrink with a type change", gp3,
			ModifyVolumeRequest{Type: VolumeGP2, SizeGiB: 50},
			false, "size", "a volume cannot shrink",
		},
	} {
		before := tc.v
		_, err := tc.v.Modify(tc.req)
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeInvalidArgument || e.Field != tc.field || e.Message != tc.message ||
			IsInvalidCombination(e) != tc.combo {
			t.Errorf(
				"%s: %v, want InvalidArgument %s %q (combination %t)",
				tc.name,
				err,
				tc.field,
				tc.message,
				tc.combo,
			)
		}
		if tc.v != before {
			t.Errorf("%s: the refusal changed the volume to %+v", tc.name, tc.v)
		}
	}
}

// #324 AC1: ModifyVolume needs at least one change, a known type and no
// negative value before any backend call.
func TestModifyVolumeRequestNormalize(t *testing.T) {
	id, err := Parse[VolumeID]("vol-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		req     ModifyVolumeRequest
		missing bool
		field   string
	}{
		{ModifyVolumeRequest{ID: id}, true, "size"},
		{ModifyVolumeRequest{ID: id, Type: "io3"}, false, "volumeType"},
		{ModifyVolumeRequest{ID: id, Type: "GP3"}, false, "volumeType"},
		{ModifyVolumeRequest{ID: id, Iops: -1}, false, "iops"},
		{ModifyVolumeRequest{ID: id, Throughput: -1}, false, "throughput"},
		{ModifyVolumeRequest{ID: id, SizeGiB: -1}, false, "size"},
	} {
		_, err := tc.req.Normalize()
		var e *Error
		if !errors.As(err, &e) || e.Field != tc.field || IsMissingParameter(e) != tc.missing {
			t.Errorf("%+v: %v, want %s (missing %t)", tc.req, err, tc.field, tc.missing)
		}
	}
	if _, err := (ModifyVolumeRequest{ID: id, Type: VolumeIO2}).Normalize(); err != nil {
		t.Errorf("type alone: %v", err)
	}
}
