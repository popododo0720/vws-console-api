package regionapi

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func seedReads(t *testing.T, set backend.Set, scope backend.Scope) map[string]resource.OperationID {
	t.Helper()
	ctx := context.Background()
	mut := func(key string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: key, Fingerprint: key}
	}
	vpc, err := set.Network.CreateVpc(ctx, mut("vpc"), resource.CreateVpcRequest{Cidr: "10.2.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Network.GetOperation(ctx, scope, vpc.Operation.ID); err != nil {
		t.Fatal(err)
	}
	sub, err := set.Network.CreateSubnet(ctx, mut("subnet"), resource.CreateSubnetRequest{
		Cidr: "10.2.0.0/24", VpcID: vpc.Items[0].ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Network.GetOperation(ctx, scope, sub.Operation.ID); err != nil {
		t.Fatal(err)
	}
	img, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	run, err := set.Compute.RunInstances(ctx, mut("run"), resource.RunInstancesRequest{
		ImageID: img, InstanceType: "vws.small", SubnetID: sub.Items[0].ID, Count: 1,
		Tags: map[string]string{"Name": "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, run.Operation.ID); err != nil {
		t.Fatal(err)
	}
	vol, err := set.Compute.CreateVolume(ctx, mut("volume"), resource.CreateVolumeRequest{
		SizeGiB: 8, Zone: resource.ZoneName, Type: resource.VolumeGP2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, vol.Operation.ID); err != nil {
		t.Fatal(err)
	}
	snap, err := set.Compute.CreateSnapshot(ctx, mut("snapshot"), resource.CreateSnapshotRequest{
		VolumeID: vol.Items[0].ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, snap.Operation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.CreateKeyPair(ctx, mut("key"), resource.CreateKeyPairRequest{
		Name: "test-key", Type: resource.KeyTypeEd25519,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := set.Network.CreateSecurityGroup(ctx, mut("sg"), resource.CreateSecurityGroupRequest{
		Name: "test-sg", VpcID: sub.Items[0].VpcID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := set.Network.AllocateAddress(ctx, mut("address"), resource.AllocateAddressRequest{
		Domain: "vpc",
	}); err != nil {
		t.Fatal(err)
	}
	return map[string]resource.OperationID{"Compute": run.Operation.ID, "Network": sub.Operation.ID}
}
