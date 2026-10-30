package backendtest

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// exerciseRootVolumeType covers #323: RunInstances creates the root volume
// with the requested type, and DescribeVolumes reads the same type back.
// An omitted type is gp2.
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
	}
}
