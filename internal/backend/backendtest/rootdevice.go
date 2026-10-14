package backendtest

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// exerciseRootDevice covers #127: an instance reports its root EBS volume,
// and DescribeVolumes lists that volume attached to it.
func exerciseRootDevice(ctx context.Context, t *testing.T, set backend.Set, account resource.AccountID, subnet resource.SubnetID, img resource.ImageID) {
	t.Helper()
	scope := backend.Scope{Account: account}
	run, err := set.Compute.RunInstances(ctx, backend.Mutation{Scope: scope, Key: "k-root", Fingerprint: "fp-root"}, resource.RunInstancesRequest{
		ImageID: img, InstanceType: "vws.small", SubnetID: subnet, Count: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{IDs: []resource.InstanceID{run.Items[0].ID}, Page: resource.PageRequest{Size: 50}})
	if err != nil || len(got.Items) != 1 {
		t.Fatalf("describe: %v %+v", err, got.Items)
	}
	inst := got.Items[0]
	if inst.RootDeviceName != resource.RootDeviceName || len(inst.BlockDevices) != 1 {
		t.Fatalf("root device: %+v", inst)
	}
	root := inst.BlockDevices[0]
	if root.Device != resource.RootDeviceName || root.VolumeID.IsZero() || !root.DeleteOnTermination {
		t.Fatalf("block device: %+v", root)
	}
	vols, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{IDs: []resource.VolumeID{root.VolumeID}, Page: resource.PageRequest{Size: 50}})
	if err != nil || len(vols.Items) != 1 {
		t.Fatalf("root volume by id: %v %+v", err, vols.Items)
	}
	vol := vols.Items[0]
	if vol.InstanceID != inst.ID || vol.Device != resource.RootDeviceName || vol.State != resource.VolumeInUse || !vol.DeleteOnTermination {
		t.Fatalf("root volume: %+v", vol)
	}
	// attachTime on the wire comes from these (#127 review): both must be set.
	if inst.LaunchTime.IsZero() || vol.CreateTime.IsZero() {
		t.Fatalf("attach time sources: launch %v create %v", inst.LaunchTime, vol.CreateTime)
	}
	all, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{Page: resource.PageRequest{Size: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range all.Items {
		if v.ID == root.VolumeID {
			return
		}
	}
	t.Fatalf("root volume missing from the list: %+v", all.Items)
}
