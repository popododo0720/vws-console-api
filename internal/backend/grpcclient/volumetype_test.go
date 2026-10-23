package grpcclient

import (
	"testing"

	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestVolumeTypeSurvivesStorage pins #323: each EC2 volume type maps to its
// own storage VolumeType and back, so gp3 no longer reads back as gp2.
func TestVolumeTypeSurvivesStorage(t *testing.T) {
	for in, want := range map[resource.VolumeType]storagev1.VolumeType{
		resource.VolumeStandard: storagev1.VolumeType_VOLUME_TYPE_STANDARD,
		resource.VolumeGP2:      storagev1.VolumeType_VOLUME_TYPE_GP2,
		resource.VolumeGP3:      storagev1.VolumeType_VOLUME_TYPE_GP3,
		resource.VolumeIO1:      storagev1.VolumeType_VOLUME_TYPE_IO1,
		resource.VolumeIO2:      storagev1.VolumeType_VOLUME_TYPE_IO2,
		resource.VolumeST1:      storagev1.VolumeType_VOLUME_TYPE_ST1,
		resource.VolumeSC1:      storagev1.VolumeType_VOLUME_TYPE_SC1,
	} {
		if got := storageType(in); got != want {
			t.Errorf("%s is sent as %s, want %s", in, got, want)
		}
		if got := volumeTypeOf(storageType(in)); got != in {
			t.Errorf("%s came back as %s", in, got)
		}
	}
}

// TestLegacySSDReadsAsGP2 pins the vws-storage#123 migration rule: a volume
// stored with the deprecated SSD tier reads as gp2.
func TestLegacySSDReadsAsGP2(t *testing.T) {
	//nolint:staticcheck // SA1019: the deprecated value is what old records carry.
	if got := volumeTypeOf(storagev1.VolumeType_VOLUME_TYPE_SSD); got != resource.VolumeGP2 {
		t.Fatalf("SSD reads as %q, want gp2", got)
	}
}

// TestVolumeTypeRefusesUnknown: a type outside the seven EBS types is never
// sent, and a stored type this build does not know is not guessed.
func TestVolumeTypeRefusesUnknown(t *testing.T) {
	for _, in := range []resource.VolumeType{"", "ssd", "GP3", "io3"} {
		if got := storageType(in); got != storagev1.VolumeType_VOLUME_TYPE_UNSPECIFIED {
			t.Errorf("%q is sent as %s, want UNSPECIFIED", in, got)
		}
	}
	for _, in := range []storagev1.VolumeType{storagev1.VolumeType_VOLUME_TYPE_UNSPECIFIED, storagev1.VolumeType(99)} {
		if got := volumeTypeOf(in); got != "" {
			t.Errorf("%s reads as %q, want empty", in, got)
		}
	}
}

// TestVolumeRecordWithUnknownTypeIsRefused: DescribeVolumes never reports a
// type it cannot name; the record is an internal error, not a guessed gp2.
func TestVolumeRecordWithUnknownTypeIsRefused(t *testing.T) {
	for _, typ := range []storagev1.VolumeType{storagev1.VolumeType_VOLUME_TYPE_UNSPECIFIED, storagev1.VolumeType(99)} {
		_, err := volumeModel(&storagev1.Volume{
			Name: volumeName("a123456789012", "vol-0123456789abcdef0"),
			Spec: &storagev1.VolumeSpec{SizeGib: 1, Type: typ},
		})
		if resource.CodeOf(err) != resource.CodeInternal {
			t.Fatalf("type %s: %v, want Internal", typ, err)
		}
	}
	got, err := volumeModel(&storagev1.Volume{
		Name: volumeName("a123456789012", "vol-0123456789abcdef0"),
		Spec: &storagev1.VolumeSpec{SizeGib: 1, Type: storagev1.VolumeType_VOLUME_TYPE_GP3},
	})
	if err != nil || got.Type != resource.VolumeGP3 {
		t.Fatalf("gp3 record: %v %+v", err, got)
	}
}
