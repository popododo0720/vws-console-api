package backendtest

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// exerciseTerminateRelease covers #392: TerminateInstances disassociates the
// instance's Elastic IP, which stays allocated, and the root volume goes
// with the instance once the terminate settles.
func exerciseTerminateRelease(
	ctx context.Context, t *testing.T, set backend.Set, account resource.AccountID,
	subnet resource.SubnetID, img resource.ImageID,
) {
	t.Helper()
	scope := backend.Scope{Account: account}
	mut := func(key string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: "k-term-" + key, Fingerprint: "fp-term-" + key}
	}
	byID := func(id resource.InstanceID) resource.InstanceQuery {
		return resource.InstanceQuery{IDs: []resource.InstanceID{id}, Page: resource.PageRequest{Size: 50}}
	}
	run, err := set.Compute.RunInstances(ctx, mut("run"), resource.RunInstancesRequest{
		ImageID: img, InstanceType: "vws.small", SubnetID: subnet, Count: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	id := run.Items[0].ID
	if _, err := set.Compute.GetOperation(ctx, scope, run.Operation.ID); err != nil {
		t.Fatal(err)
	}
	got, err := set.Compute.DescribeInstances(ctx, scope, byID(id))
	if err != nil || len(got.Items) != 1 || len(got.Items[0].BlockDevices) != 1 {
		t.Fatalf("describe launched: %v %+v", err, got.Items)
	}
	root := got.Items[0].BlockDevices[0].VolumeID
	eip, err := set.Network.AllocateAddress(ctx, mut("addr"), resource.AllocateAddressRequest{Domain: "vpc"})
	if err != nil {
		t.Fatal(err)
	}
	addr := eip.Items[0].ID
	if _, err := set.Network.AssociateAddress(ctx, mut("assoc"), resource.AssociateAddressRequest{
		ID: addr, InstanceID: id,
	}); err != nil {
		t.Fatal(err)
	}
	terminated, err := set.Compute.TerminateInstances(ctx, mut("eip"), resource.TerminateInstancesRequest{
		IDs: []resource.InstanceID{id},
	})
	if err != nil || terminated.Items[0].Current != resource.InstanceShuttingDown {
		t.Fatalf("terminate an instance with an address: %v %+v", err, terminated.Items)
	}
	addrs, err := set.Network.DescribeAddresses(ctx, scope, resource.AddressQuery{
		IDs: []resource.AddressID{addr}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(addrs.Items) != 1 || !addrs.Items[0].InstanceID.IsZero() {
		t.Fatalf("address after terminate is allocated and free: %v %+v", err, addrs.Items)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, terminated.Operation.ID); err != nil {
		t.Fatal(err)
	}
	done, err := set.Compute.DescribeInstances(ctx, scope, byID(id))
	if err != nil || done.Items[0].State != resource.InstanceTerminated {
		t.Fatalf("terminated: %v %+v", err, done.Items)
	}
	vols, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{Page: resource.PageRequest{Size: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vols.Items {
		if v.ID == root {
			t.Fatalf("root volume %s outlived its terminated instance: %+v", root, v)
		}
	}
	if _, err := set.Network.ReleaseAddress(ctx, mut("rel"), resource.ReleaseAddressRequest{ID: addr}); err != nil {
		t.Fatalf("release the freed address: %v", err)
	}
}
