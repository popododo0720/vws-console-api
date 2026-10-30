package backendtest

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// exerciseRootVolumeType covers #323: RunInstances creates the root volume
// with the requested type, and DescribeVolumes reads the same type back.
// An omitted type is gp2, and a gp3 root volume gets the gp3 Iops and
// Throughput defaults. The mapping's Iops and Throughput (#324) reach the
// root volume and read back.
func exerciseRootVolumeType(
	ctx context.Context, t *testing.T, set backend.Set,
	account resource.AccountID, subnet resource.SubnetID, img resource.ImageID,
) {
	t.Helper()
	scope := backend.Scope{Account: account}
	for _, typ := range []resource.VolumeType{"", resource.VolumeStandard, resource.VolumeGP2, resource.VolumeGP3} {
		want := typ
		if typ == "" {
			want = resource.VolumeGP2
		}
		key := "k-root-type-" + string(want)
		if typ == "" {
			key = "k-root-type-omitted"
		}
		mut := backend.Mutation{Scope: scope, Key: key, Fingerprint: "fp-" + key}
		run, err := set.Compute.RunInstances(ctx, mut, resource.RunInstancesRequest{
			ImageID: img, InstanceType: "vws.small", SubnetID: subnet, Count: 1, RootVolumeType: typ,
		})
		if err != nil {
			t.Fatalf("run with root type %q: %v", typ, err)
		}
		got, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{
			IDs: []resource.InstanceID{run.Items[0].ID}, Page: resource.PageRequest{Size: 50},
		})
		if err != nil || len(got.Items) != 1 || len(got.Items[0].BlockDevices) != 1 {
			t.Fatalf("describe with root type %q: %v %+v", typ, err, got.Items)
		}
		root := got.Items[0].BlockDevices[0].VolumeID
		vols, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{
			IDs: []resource.VolumeID{root}, Page: resource.PageRequest{Size: 50},
		})
		if err != nil || len(vols.Items) != 1 {
			t.Fatalf("root volume with root type %q: %v %+v", typ, err, vols.Items)
		}
		if vols.Items[0].Type != want {
			t.Fatalf("root type %q reads back as %q, want %q", typ, vols.Items[0].Type, want)
		}
		// gp3 gets 3,000 IOPS and 125 MiB/s, as on CreateVolume.
		var iops, miBps int64
		if want == resource.VolumeGP3 {
			iops, miBps = 3000, 125
		}
		if vols.Items[0].Iops != iops || vols.Items[0].Throughput != miBps {
			t.Fatalf("root type %q: %d IOPS %d MiB/s, want %d and %d",
				typ, vols.Items[0].Iops, vols.Items[0].Throughput, iops, miBps)
		}
	}
	for _, want := range []resource.RunInstancesRequest{
		{RootVolumeType: resource.VolumeGP3, RootIops: 4000, RootThroughput: 250},
		{RootVolumeType: resource.VolumeIO1, RootIops: 400},
		{RootVolumeType: resource.VolumeIO2, RootIops: 8000},
	} {
		key := "k-root-perf-" + string(want.RootVolumeType)
		req := want
		req.ImageID, req.InstanceType, req.SubnetID, req.Count = img, "vws.small", subnet, 1
		run, err := set.Compute.RunInstances(ctx, backend.Mutation{Scope: scope, Key: key, Fingerprint: "fp-" + key}, req)
		if err != nil {
			t.Fatalf("run with root %s %d IOPS: %v", want.RootVolumeType, want.RootIops, err)
		}
		got, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{
			IDs: []resource.InstanceID{run.Items[0].ID}, Page: resource.PageRequest{Size: 50},
		})
		if err != nil || len(got.Items) != 1 || len(got.Items[0].BlockDevices) != 1 {
			t.Fatalf("describe with root %s: %v %+v", want.RootVolumeType, err, got.Items)
		}
		vols, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{
			IDs: []resource.VolumeID{got.Items[0].BlockDevices[0].VolumeID}, Page: resource.PageRequest{Size: 50},
		})
		if err != nil || len(vols.Items) != 1 {
			t.Fatalf("root volume %s: %v %+v", want.RootVolumeType, err, vols.Items)
		}
		v := vols.Items[0]
		if v.Type != want.RootVolumeType || v.Iops != want.RootIops || v.Throughput != want.RootThroughput {
			t.Fatalf("root %s %d IOPS %d MiB/s reads back as %s %d IOPS %d MiB/s",
				want.RootVolumeType, want.RootIops, want.RootThroughput, v.Type, v.Iops, v.Throughput)
		}
	}
}
