package fake

import (
	"context"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// DeleteVolume follows Instance.BlockDevices. An available row that an
// instance still names stays a conflict.
func TestDeleteVolumeFollowsBlockDevices(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	w := New(Options{Now: func() time.Time { return now }})
	set := w.Set()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	img, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	sub, err := set.Network.CreateSubnet(ctx, backend.Mutation{Scope: scope, Key: "sub", Fingerprint: "sub"}, resource.CreateSubnetRequest{Cidr: "10.9.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Network.GetOperation(ctx, scope, sub.Operation.ID); err != nil {
		t.Fatal(err)
	}
	run, err := set.Compute.RunInstances(ctx, backend.Mutation{Scope: scope, Key: "run", Fingerprint: "run"}, resource.RunInstancesRequest{
		ImageID: img, InstanceType: "vws.small", SubnetID: sub.Items[0].ID, Count: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, run.Operation.ID); err != nil {
		t.Fatal(err)
	}
	vol, err := set.Compute.CreateVolume(ctx, backend.Mutation{Scope: scope, Key: "vol", Fingerprint: "vol"}, resource.CreateVolumeRequest{
		SizeGiB: 4, Zone: resource.ZoneName,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, vol.Operation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.AttachVolume(ctx, backend.Mutation{Scope: scope, Key: "attach", Fingerprint: "attach"}, resource.AttachVolumeRequest{
		VolumeID: vol.Items[0].ID, InstanceID: run.Items[0].ID, Device: "/dev/sdf",
	}); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	w.vol[vol.Items[0].ID].State = resource.VolumeAvailable
	w.mu.Unlock()
	if _, err := set.Compute.DeleteVolume(ctx, backend.Mutation{Scope: scope, Key: "del", Fingerprint: "del"}, resource.DeleteVolumeRequest{
		ID: vol.Items[0].ID,
	}); resource.CodeOf(err) != resource.CodeConflict || resource.AsError(err).Kind != resource.KindVolume {
		t.Fatalf("delete while a block device names the volume: %v", err)
	}
}
