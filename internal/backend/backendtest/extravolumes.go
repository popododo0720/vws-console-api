package backendtest

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// exerciseLaunchExtraVolumes covers #423 AC2 and AC3 for the volumes of
// non-root mappings: each instance gets its own volume per mapping, attached
// at the device with the mapping's size, type, performance and
// DeleteOnTermination, and a retry with the token returns the same ones.
// Once an instance terminates, its default volume is gone and its kept one is
// available with no attachment, so its DetachVolume is VolumeNotInUse; the
// other instance's volumes stay. A default volume is not the root device, so
// it detaches while its instance runs, and the root still does not.
func exerciseLaunchExtraVolumes(
	ctx context.Context, t *testing.T, set backend.Set,
	account resource.AccountID, subnet resource.SubnetID, img resource.ImageID,
) {
	t.Helper()
	scope := backend.Scope{Account: account}
	mut := func(step string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: "k-extra" + step, Fingerprint: "fp-extra" + step}
	}
	extras := []resource.LaunchVolume{
		{Device: "/dev/sdf", SizeGiB: 20, Type: resource.VolumeGP3},
		{Device: "/dev/sdg", SizeGiB: 125, Type: resource.VolumeST1, Kept: true},
		{Device: "xvdh", SizeGiB: 10, Type: resource.VolumeIO1, Iops: 500},
	}
	req := resource.RunInstancesRequest{
		ImageID: img, InstanceType: "vws.small", SubnetID: subnet, Count: 2, ExtraVolumes: extras,
	}
	run, err := set.Compute.RunInstances(ctx, mut(""), req)
	if err != nil || len(run.Items) != 2 {
		t.Fatalf("run with extra volumes: %v %+v", err, run.Items)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, run.Operation.ID); err != nil {
		t.Fatal(err)
	}
	ids := []resource.InstanceID{run.Items[0].ID, run.Items[1].ID}
	got, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{
		IDs: ids, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(got.Items) != 2 {
		t.Fatalf("describe: %v %+v", err, got.Items)
	}
	// byInstance is each instance's volume id at each extra device.
	byInstance := map[resource.InstanceID][]resource.VolumeID{}
	seen := map[resource.VolumeID]bool{}
	for _, inst := range got.Items {
		if len(inst.BlockDevices) != 1+len(extras) || inst.BlockDevices[0].Device != resource.RootDeviceName {
			t.Fatalf("instance %s block devices %+v", inst.ID, inst.BlockDevices)
		}
		for _, block := range inst.BlockDevices {
			if seen[block.VolumeID] {
				t.Fatalf("volume %s is on two block devices", block.VolumeID)
			}
			seen[block.VolumeID] = true
		}
		for j, extra := range extras {
			block := inst.BlockDevices[1+j]
			if block.Device != extra.Device || block.DeleteOnTermination == extra.Kept ||
				block.Status != resource.AttachmentAttached {
				t.Fatalf("instance %s extra %d: block device %+v, want %+v", inst.ID, j, block, extra)
			}
			byInstance[inst.ID] = append(byInstance[inst.ID], block.VolumeID)
			vols, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{
				IDs: []resource.VolumeID{block.VolumeID}, Page: resource.PageRequest{Size: 50},
			})
			if err != nil || len(vols.Items) != 1 {
				t.Fatalf("extra volume %s: %v %+v", block.VolumeID, err, vols.Items)
			}
			iops, miBps := extra.Performance()
			if v := vols.Items[0]; v.State != resource.VolumeInUse || v.InstanceID != inst.ID ||
				v.Device != extra.Device || v.AttachState != resource.AttachmentAttached ||
				v.DeleteOnTermination == extra.Kept || v.SizeGiB != extra.SizeGiB ||
				v.Type != extra.VolumeType() || v.Iops != iops || v.Throughput != miBps {
				t.Fatalf("extra volume %d of %s: %+v, want %+v", j, inst.ID, v, extra)
			}
		}
	}
	again, err := set.Compute.RunInstances(ctx, mut(""), req)
	if err != nil || len(again.Items) != 2 {
		t.Fatalf("replay: %v %+v", err, again.Items)
	}
	for i, inst := range again.Items {
		if inst.ID != ids[i] {
			t.Fatalf("replay launched %s, want %s", inst.ID, ids[i])
		}
	}
	terminated, err := set.Compute.TerminateInstances(ctx, mut("-term"), resource.TerminateInstancesRequest{
		IDs: []resource.InstanceID{ids[0]},
	})
	if err != nil {
		t.Fatalf("terminate: %v", err)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, terminated.Operation.ID); err != nil {
		t.Fatal(err)
	}
	all, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{Page: resource.PageRequest{Size: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	listed := func(id resource.VolumeID) []resource.Volume {
		var out []resource.Volume
		for _, v := range all.Items {
			if v.ID == id {
				out = append(out, v)
			}
		}
		return out
	}
	for j, extra := range extras {
		gone, other := byInstance[ids[0]][j], byInstance[ids[1]][j]
		if left := listed(other); len(left) != 1 || left[0].State != resource.VolumeInUse {
			t.Fatalf("extra %d of the instance left running: %+v", j, left)
		}
		left := listed(gone)
		if !extra.Kept {
			if len(left) != 0 {
				t.Fatalf("a default extra volume outlived its terminated instance: %+v", left)
			}
			continue
		}
		if len(left) != 1 {
			t.Fatalf("a kept extra volume is not listed after its instance terminated: %+v", all.Items)
		}
		if v := left[0]; v.State != resource.VolumeAvailable || !v.InstanceID.IsZero() || v.Device != "" ||
			v.AttachState != "" || v.DeleteOnTermination {
			t.Fatalf("a kept extra volume after terminate is not available and detached: %+v", v)
		}
		_, err := set.Compute.DetachVolume(ctx, mut("-detach"), resource.DetachVolumeRequest{VolumeID: gone})
		if want := resource.VolumeNotInUse(gone); resource.CodeOf(err) != resource.CodeOf(want) ||
			resource.AsError(err).Message != resource.AsError(want).Message {
			t.Fatalf("detach the kept extra volume: %v, want %v", err, want)
		}
		if _, err := set.Compute.DeleteVolume(ctx, mut("-del"), resource.DeleteVolumeRequest{ID: gone}); err != nil {
			t.Fatalf("delete the kept extra volume: %v", err)
		}
	}
	running, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{
		IDs: ids[1:], Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(running.Items) != 1 {
		t.Fatalf("describe the instance left running: %v %+v", err, running.Items)
	}
	root := running.Items[0].BlockDevices[0].VolumeID
	if _, err := set.Compute.DetachVolume(ctx, mut("-detach-root"), resource.DetachVolumeRequest{
		VolumeID: root,
	}); resource.CodeOf(err) != resource.CodeOf(resource.VolumeRootDevice(root)) {
		t.Fatalf("detach the root volume: %v, want %v", err, resource.VolumeRootDevice(root))
	}
	if _, err := set.Compute.DetachVolume(ctx, mut("-detach-default"), resource.DetachVolumeRequest{
		VolumeID: byInstance[ids[1]][0],
	}); err != nil {
		t.Fatalf("detach the default extra volume at %s: %v", extras[0].Device, err)
	}
}
