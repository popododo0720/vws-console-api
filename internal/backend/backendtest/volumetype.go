package backendtest

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// exerciseVolumeTypes covers #323: every EBS volume type a backend stores
// reads back as the same type from CreateVolume, DescribeVolumes and after
// ModifyVolume, and a type that is not an EBS type is refused with nothing
// created. Which types CreateVolume accepts on the wire is the surface's
// job (resource.CreateVolumeRequest.Normalize); this pins the backends.
func exerciseVolumeTypes(ctx context.Context, t *testing.T, set backend.Set, account resource.AccountID) {
	t.Helper()
	scope := backend.Scope{Account: account}
	mut := func(step string, typ resource.VolumeType) backend.Mutation {
		key := "voltype-" + step + "-" + string(typ)
		return backend.Mutation{Scope: scope, Key: "k-" + key, Fingerprint: "fp-" + key}
	}
	describe := func(id resource.VolumeID) []resource.Volume {
		t.Helper()
		got, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{
			IDs: []resource.VolumeID{id}, Page: resource.PageRequest{Size: 50},
		})
		if err != nil {
			t.Fatalf("describe %s: %v", id, err)
		}
		return got.Items
	}
	live := func() int {
		t.Helper()
		all, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{Page: resource.PageRequest{Size: 1000}})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, v := range all.Items {
			if v.State != resource.VolumeDeleting {
				n++
			}
		}
		return n
	}
	before := live()
	for _, typ := range []resource.VolumeType{
		resource.VolumeStandard, resource.VolumeGP2, resource.VolumeGP3,
		resource.VolumeIO1, resource.VolumeIO2, resource.VolumeST1, resource.VolumeSC1,
	} {
		created, err := set.Compute.CreateVolume(ctx, mut("create", typ), resource.CreateVolumeRequest{
			SizeGiB: 125, Zone: resource.ZoneName, Type: typ,
		})
		if err != nil {
			t.Fatalf("create %s: %v", typ, err)
		}
		if got := created.Items[0].Type; got != typ {
			t.Fatalf("create %s returned %s", typ, got)
		}
		id := created.Items[0].ID
		if got := describe(id); len(got) != 1 || got[0].Type != typ {
			t.Fatalf("%s reads back as %+v", typ, got)
		}
		grow := resource.ModifyVolumeRequest{ID: id, SizeGiB: 126}
		if _, err := set.Compute.ModifyVolume(ctx, mut("modify", typ), grow); err != nil {
			t.Fatalf("modify %s: %v", typ, err)
		}
		if got := describe(id); len(got) != 1 || got[0].Type != typ {
			t.Fatalf("%s after modify: %+v", typ, got)
		}
		if _, err := set.Compute.DeleteVolume(ctx, mut("delete", typ), resource.DeleteVolumeRequest{ID: id}); err != nil {
			t.Fatalf("delete %s: %v", typ, err)
		}
	}
	for _, typ := range []resource.VolumeType{"", "ssd", "GP3", "io3"} {
		_, err := set.Compute.CreateVolume(ctx, mut("bad", typ), resource.CreateVolumeRequest{
			SizeGiB: 8, Zone: resource.ZoneName, Type: typ,
		})
		if resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Fatalf("create %q: %v, want InvalidArgument", typ, err)
		}
	}
	if after := live(); after != before {
		t.Fatalf("volume types left %d live volumes, want %d", after, before)
	}
}
