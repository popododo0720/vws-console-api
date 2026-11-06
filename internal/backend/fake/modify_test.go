package fake

import (
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// #324 review: two ModifyVolume operations pending at once each land only
// what their request changed, and the size never shrinks, as vws-storage
// stores max(stored, target). Pending operations settle in map order, so the
// test repeats to cover both orders.
func TestOverlappingModifiesKeepBothChanges(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account}
	m := func(k string) backend.Mutation { return backend.Mutation{Scope: scope, Key: k, Fingerprint: k} }
	for range 20 {
		now := time.Unix(1_700_000_000, 0).UTC()
		set := New(Options{Now: func() time.Time { return now }, Latency: time.Second, Entropy: &Sequence{}}).Set()
		created, err := set.Compute.CreateVolume(t.Context(), m("create"), resource.CreateVolumeRequest{
			SizeGiB: 10, Zone: resource.ZoneName, Type: resource.VolumeGP2,
		})
		if err != nil {
			t.Fatal(err)
		}
		id := created.Items[0].ID
		now = now.Add(2 * time.Second)
		grow := resource.ModifyVolumeRequest{ID: id, SizeGiB: 200}
		if _, err := set.Compute.ModifyVolume(t.Context(), m("grow"), grow); err != nil {
			t.Fatal(err)
		}
		retype := resource.ModifyVolumeRequest{ID: id, Type: resource.VolumeGP3}
		if _, err := set.Compute.ModifyVolume(t.Context(), m("retype"), retype); err != nil {
			t.Fatal(err)
		}
		now = now.Add(2 * time.Second)
		page, err := set.Compute.DescribeVolumes(t.Context(), scope, resource.VolumeQuery{
			IDs: []resource.VolumeID{id}, Page: resource.PageRequest{Size: 1},
		})
		if err != nil {
			t.Fatal(err)
		}
		if v := page.Items[0]; v.SizeGiB != 200 || v.Type != resource.VolumeGP3 || v.Iops != 3000 || v.Throughput != 125 {
			t.Fatalf("grow to 200 GiB then retype to gp3 settled as %s at %d GiB, %d IOPS, %d MiB/s",
				v.Type, v.SizeGiB, v.Iops, v.Throughput)
		}
	}
}
