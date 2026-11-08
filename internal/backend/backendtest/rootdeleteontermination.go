package backendtest

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// exerciseRootDeleteOnTermination covers #423 AC3 for the root volume: the
// root mapping's Ebs.DeleteOnTermination reads back on the instance's block
// device and on the volume's attachment. Once the instance terminates, a
// default root is gone and a kept one is available with no attachment, as
// EC2 reports a volume it detached.
func exerciseRootDeleteOnTermination(
	ctx context.Context, t *testing.T, set backend.Set,
	account resource.AccountID, subnet resource.SubnetID, img resource.ImageID,
) {
	t.Helper()
	scope := backend.Scope{Account: account}
	for _, kept := range []bool{false, true} {
		key := "k-root-dot-default"
		if kept {
			key = "k-root-dot-kept"
		}
		mut := func(step string) backend.Mutation {
			return backend.Mutation{Scope: scope, Key: key + step, Fingerprint: "fp-" + key + step}
		}
		run, err := set.Compute.RunInstances(ctx, mut(""), resource.RunInstancesRequest{
			ImageID: img, InstanceType: "vws.small", SubnetID: subnet, Count: 1, RootVolumeKept: kept,
		})
		if err != nil {
			t.Fatalf("run with the root kept %v: %v", kept, err)
		}
		id := run.Items[0].ID
		if _, err := set.Compute.GetOperation(ctx, scope, run.Operation.ID); err != nil {
			t.Fatal(err)
		}
		got, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{
			IDs: []resource.InstanceID{id}, Page: resource.PageRequest{Size: 50},
		})
		if err != nil || len(got.Items) != 1 || len(got.Items[0].BlockDevices) != 1 {
			t.Fatalf("describe with the root kept %v: %v %+v", kept, err, got.Items)
		}
		block := got.Items[0].BlockDevices[0]
		if block.Device != resource.RootDeviceName || block.DeleteOnTermination == kept {
			t.Fatalf("root kept %v: block device %+v", kept, block)
		}
		byID := resource.VolumeQuery{IDs: []resource.VolumeID{block.VolumeID}, Page: resource.PageRequest{Size: 50}}
		vols, err := set.Compute.DescribeVolumes(ctx, scope, byID)
		if err != nil || len(vols.Items) != 1 {
			t.Fatalf("root volume with the root kept %v: %v %+v", kept, err, vols.Items)
		}
		if v := vols.Items[0]; v.State != resource.VolumeInUse || v.InstanceID != id || v.DeleteOnTermination == kept {
			t.Fatalf("root kept %v: volume %+v", kept, v)
		}
		terminated, err := set.Compute.TerminateInstances(ctx, mut("-term"), resource.TerminateInstancesRequest{
			IDs: []resource.InstanceID{id},
		})
		if err != nil {
			t.Fatalf("terminate with the root kept %v: %v", kept, err)
		}
		if _, err := set.Compute.GetOperation(ctx, scope, terminated.Operation.ID); err != nil {
			t.Fatal(err)
		}
		all, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{Page: resource.PageRequest{Size: 1000}})
		if err != nil {
			t.Fatal(err)
		}
		var left []resource.Volume
		for _, v := range all.Items {
			if v.ID == block.VolumeID {
				left = append(left, v)
			}
		}
		if !kept {
			if len(left) != 0 {
				t.Fatalf("a default root outlived its terminated instance: %+v", left)
			}
			continue
		}
		if len(left) != 1 {
			t.Fatalf("a kept root is not listed after its instance terminated: %+v", all.Items)
		}
		after, err := set.Compute.DescribeVolumes(ctx, scope, byID)
		if err != nil || len(after.Items) != 1 {
			t.Fatalf("kept root by id after terminate: %v %+v", err, after.Items)
		}
		for _, v := range []resource.Volume{left[0], after.Items[0]} {
			if v.State != resource.VolumeAvailable || !v.InstanceID.IsZero() || v.Device != "" ||
				v.AttachState != "" || v.DeleteOnTermination {
				t.Fatalf("a kept root after terminate is not available and detached: %+v", v)
			}
		}
		del := resource.DeleteVolumeRequest{ID: block.VolumeID}
		if _, err := set.Compute.DeleteVolume(ctx, mut("-del"), del); err != nil {
			t.Fatalf("delete the kept root: %v", err)
		}
	}
}
