package backendtest

import (
	"context"
	"strconv"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// exerciseVolumeTypes covers #323 and #324: every EBS volume type a backend stores
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
	maxGiB := map[resource.VolumeType]int64{
		resource.VolumeStandard: 1024, resource.VolumeGP2: 16384, resource.VolumeGP3: 65536,
		resource.VolumeIO1: 16384, resource.VolumeIO2: 65536, resource.VolumeST1: 16384, resource.VolumeSC1: 16384,
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
		// #324 AC1: ModifyVolume Size stops at the type's EC2 maximum.
		over := resource.ModifyVolumeRequest{ID: id, SizeGiB: maxGiB[typ] + 1}
		_, err = set.Compute.ModifyVolume(ctx, mut("modify-over", typ), over)
		if resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Fatalf("modify %s to %d GiB: %v, want InvalidArgument", typ, over.SizeGiB, err)
		}
		if got := describe(id); len(got) != 1 || got[0].SizeGiB != 126 {
			t.Fatalf("%s after a refused grow: %+v", typ, got)
		}
		if _, err := set.Compute.DeleteVolume(ctx, mut("delete", typ), resource.DeleteVolumeRequest{ID: id}); err != nil {
			t.Fatalf("delete %s: %v", typ, err)
		}
	}
	// #324: provisioned Iops and Throughput are stored and read back.
	for _, want := range []resource.CreateVolumeRequest{
		{SizeGiB: 125, Zone: resource.ZoneName, Type: resource.VolumeGP3, Iops: 4000, Throughput: 250},
		{SizeGiB: 125, Zone: resource.ZoneName, Type: resource.VolumeIO2, Iops: 1000},
	} {
		created, err := set.Compute.CreateVolume(ctx, mut("perf", want.Type), want)
		if err != nil {
			t.Fatalf("create %s with iops: %v", want.Type, err)
		}
		if got := created.Items[0]; got.Iops != want.Iops || got.Throughput != want.Throughput {
			t.Fatalf("create %s returned iops %d throughput %d", want.Type, got.Iops, got.Throughput)
		}
		id := created.Items[0].ID
		if got := describe(id); len(got) != 1 || got[0].Iops != want.Iops || got[0].Throughput != want.Throughput {
			t.Fatalf("%s with iops reads back as %+v", want.Type, got)
		}
		del := resource.DeleteVolumeRequest{ID: id}
		if _, err := set.Compute.DeleteVolume(ctx, mut("perf-delete", want.Type), del); err != nil {
			t.Fatalf("delete %s: %v", want.Type, err)
		}
	}
	// #324 AC1: one ModifyVolume changes size, type, Iops and Throughput
	// together, and the result reads back. A gp2 volume of 10 GiB becomes st1
	// only with the 125 GiB grow in the same call.
	created, err := set.Compute.CreateVolume(ctx, mut("retype", resource.VolumeGP2), resource.CreateVolumeRequest{
		SizeGiB: 10, Zone: resource.ZoneName, Type: resource.VolumeGP2,
	})
	if err != nil {
		t.Fatalf("create gp2 to retype: %v", err)
	}
	id := created.Items[0].ID
	shape := func(v resource.Volume) resource.Volume {
		return resource.Volume{Type: v.Type, SizeGiB: v.SizeGiB, Iops: v.Iops, Throughput: v.Throughput}
	}
	for _, step := range []struct {
		req  resource.ModifyVolumeRequest
		want resource.Volume
	}{
		{
			resource.ModifyVolumeRequest{ID: id, Type: resource.VolumeST1, SizeGiB: 125},
			resource.Volume{Type: resource.VolumeST1, SizeGiB: 125},
		},
		{
			resource.ModifyVolumeRequest{ID: id, Type: resource.VolumeGP3},
			resource.Volume{Type: resource.VolumeGP3, SizeGiB: 125, Iops: 3000, Throughput: 125},
		},
		{
			resource.ModifyVolumeRequest{ID: id, Iops: 6000, Throughput: 500},
			resource.Volume{Type: resource.VolumeGP3, SizeGiB: 125, Iops: 6000, Throughput: 500},
		},
		{
			resource.ModifyVolumeRequest{ID: id, Type: resource.VolumeIO2, SizeGiB: 200, Iops: 20000},
			resource.Volume{Type: resource.VolumeIO2, SizeGiB: 200, Iops: 20000},
		},
	} {
		key := string(step.want.Type) + "-" + strconv.FormatInt(step.want.Iops, 10)
		acc, err := set.Compute.ModifyVolume(ctx, mut("retype-"+key, step.want.Type), step.req)
		if err != nil {
			t.Fatalf("modify %+v: %v", step.req, err)
		}
		if got := shape(acc.Items[0]); got != step.want {
			t.Fatalf("modify %+v returned %+v, want %+v", step.req, got, step.want)
		}
		if got := describe(id); len(got) != 1 || shape(got[0]) != step.want {
			t.Fatalf("after modify %+v: %+v, want %+v", step.req, got, step.want)
		}
	}
	illegal := resource.ModifyVolumeRequest{ID: id, Type: resource.VolumeGP2, Throughput: 200}
	_, err = set.Compute.ModifyVolume(ctx, mut("retype-illegal", resource.VolumeGP2), illegal)
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("modify to gp2 with throughput: %v, want InvalidArgument", err)
	}
	if got := describe(id); len(got) != 1 || shape(got[0]) != shape(resource.Volume{
		Type: resource.VolumeIO2, SizeGiB: 200, Iops: 20000,
	}) {
		t.Fatalf("a refused modify changed the volume: %+v", got)
	}
	del := resource.DeleteVolumeRequest{ID: id}
	if _, err := set.Compute.DeleteVolume(ctx, mut("retype-delete", resource.VolumeIO2), del); err != nil {
		t.Fatalf("delete retyped volume: %v", err)
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
