package cloud

import (
	"errors"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestCreateVolumeUsesRegionalZones(t *testing.T) {
	for _, tc := range []struct {
		name, zone, want string
		valid            bool
	}{
		{"regional", "pve-test-1a", "pve-test-1a", true},
		{"regional default", "", "pve-test-1a", true},
		{"legacy zone", resource.ZoneName, "", false},
		{"foreign region", "pve-other-1a", "", false},
		{"malicious", "../../etc/passwd", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := (backend.AllSupported{Kind: resource.RegionKindProxmox}).RegionCapabilities(t.Context(), "pve-test-1")
			if err != nil {
				t.Fatal(err)
			}
			doc.Zones = []resource.RegionZone{{ZoneName: "pve-test-1a", State: "available"}}
			set := fake.New(fake.Options{}).Set()
			svc := New(Config{Backends: set, Capabilities: stubCapabilities{doc: doc}})
			c := caller(t)
			c.Region = "pve-test-1"
			acc, err := svc.CreateVolume(t.Context(), c, token(t, "regional-volume"),
				resource.CreateVolumeRequest{SizeGiB: 1, Zone: tc.zone})
			if tc.valid {
				if err != nil || len(acc.Items) != 1 || acc.Items[0].Zone != tc.want {
					t.Fatalf("regional volume: %+v, %v; want zone %s", acc, err, tc.want)
				}
			} else if resource.CodeOf(err) != resource.CodeInvalidArgument {
				t.Fatalf("unregistered zone: %v", err)
			}
			page, err := set.Compute.DescribeVolumes(t.Context(), scope(c), resource.VolumeQuery{
				Page: resource.PageRequest{Size: 100},
			})
			wantCount := 0
			if tc.valid {
				wantCount = 1
			}
			if err != nil || len(page.Items) != wantCount {
				t.Fatalf("volume writes: %+v, %v; want %d", page, err, wantCount)
			}
		})
	}
}

func TestCreateVolumeRefusesUnreadableZones(t *testing.T) {
	failure := errors.New("capabilities unavailable")
	svc, _, c := gatedService(t, stubCapabilities{err: failure})
	_, err := svc.CreateVolume(t.Context(), c, token(t, "volume"), resource.CreateVolumeRequest{SizeGiB: 1})
	if !errors.Is(err, failure) {
		t.Fatalf("unreadable zone catalog: %v", err)
	}
}
