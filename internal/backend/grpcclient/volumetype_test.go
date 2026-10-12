package grpcclient

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestVolumeTypeSurvivesStorage(t *testing.T) {
	for in, want := range map[resource.VolumeType]resource.VolumeType{
		resource.VolumeStandard: resource.VolumeStandard,
		resource.VolumeGP2:      resource.VolumeGP2,
		resource.VolumeGP3:      resource.VolumeGP2,
	} {
		if got := volumeTypeOf(storageType(in)); got != want {
			t.Fatalf("%s came back as %s, want %s", in, got, want)
		}
	}
}
