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
func TestCheckGrowRefusesAboveTypeMaximum(t *testing.T) {
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
		err := v.CheckGrow(tc.size)
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeInvalidArgument || e.Field != "size" || e.Message != tc.want {
			t.Errorf("grow %d GiB: %v, want InvalidArgument size %q", tc.size, err, tc.want)
		}
	}
	if v.SizeGiB != 2048 {
		t.Fatalf("a refused grow changed the volume to %d GiB", v.SizeGiB)
	}
}
