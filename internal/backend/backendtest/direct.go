package backendtest

import (
	"context"
	"maps"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// DirectSubnet and DirectCidr are the direct network a DirectNetworks
// harness serves.
const (
	DirectSubnet = "subnet-direct-prod"
	DirectCidr   = "192.168.200.0/24"
)

// DirectNetworks is the direct network table (#60). Every account sees the
// direct subnet as its own, in vpc-direct and tagged direct, in a listing
// and by id, from any client set. CreateSubnet in vpc-direct, DeleteSubnet
// and CreateTags on a direct subnet are PermissionDenied and change nothing,
// not even another subnet in the same tag batch.
//
// Its accounts are its own, so it may share a world with Run.
func DirectNetworks(t *testing.T, newSet Harness) {
	t.Helper()
	ctx := context.Background()
	direct := parse[resource.SubnetID](t, DirectSubnet)
	owner := parse[resource.AccountID](t, "456789012345")
	scope := backend.Scope{Account: owner}
	set := newSet()
	for _, raw := range []string{"456789012345", "567890123456"} {
		account := parse[resource.AccountID](t, raw)
		for _, s := range []backend.Set{set, newSet()} {
			checkDirectVisible(ctx, t, s, account, direct)
		}
	}

	mut := func(key string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: "dn-" + key, Fingerprint: "fp-dn-" + key}
	}
	own, err := set.Network.CreateSubnet(ctx, mut("own"), resource.CreateSubnetRequest{Cidr: "10.7.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Network.GetOperation(ctx, scope, own.Operation.ID); err != nil {
		t.Fatal(err)
	}
	ownID := own.Items[0].ID
	if _, err := set.Network.CreateSubnet(ctx, mut("create"), resource.CreateSubnetRequest{
		Cidr: "192.168.200.0/25", VpcID: resource.DirectVpcID(), Zone: resource.ZoneName,
	}); resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Fatalf("CreateSubnet in vpc-direct: %v, want PermissionDenied", err)
	}
	_, err = set.Network.DeleteSubnet(ctx, mut("delete"), resource.DeleteSubnetRequest{ID: direct})
	if resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Fatalf("DeleteSubnet of a direct subnet: %v, want PermissionDenied", err)
	}
	if _, err := set.Network.TagSubnets(ctx, mut("tag"), resource.TagSubnetsRequest{
		IDs: []resource.SubnetID{ownID, direct}, Tags: map[string]string{"owner": "me"},
	}); resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Fatalf("CreateTags on a direct subnet: %v, want PermissionDenied", err)
	}
	got, err := set.Network.DescribeSubnets(ctx, scope, resource.SubnetQuery{
		IDs: []resource.SubnetID{ownID}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(got.Items) != 1 || len(got.Items[0].Tags) != 0 {
		t.Fatalf("a refused batch tagged the other subnet: %v %+v", err, got.Items)
	}
	checkDirectVisible(ctx, t, set, owner, direct)
	directLaunch(ctx, t, newSet, ownID, direct)
}

// directLaunch launches with interfaces on overlay and direct subnets. The
// interfaces come back in device order, on any client set, after a retry
// and after a stop and start. Any account may use a direct subnet, but only
// its own overlay subnets. A launch naming a missing subnet launches
// nothing.
func directLaunch(ctx context.Context, t *testing.T, newSet Harness, overlay, direct resource.SubnetID) {
	t.Helper()
	set := newSet()
	owner := parse[resource.AccountID](t, "456789012345")
	other := parse[resource.AccountID](t, "567890123456")
	img := parse[resource.ImageID](t, "ami-0123456789abcdef0")
	mut := func(account resource.AccountID, key string) backend.Mutation {
		return backend.Mutation{Scope: backend.Scope{Account: account}, Key: "dl-" + key, Fingerprint: "fp-dl-" + key}
	}
	launch := func(
		m backend.Mutation, nics ...resource.NetworkInterfaceSpec,
	) (resource.Accepted[resource.Instance], error) {
		return set.Compute.RunInstances(ctx, m, resource.RunInstancesRequest{
			ImageID: img, InstanceType: "vws.small", Count: 1, NetworkInterfaces: nics,
		})
	}
	read := func(s backend.Set, account resource.AccountID, id resource.InstanceID) resource.Instance {
		t.Helper()
		page, err := s.Compute.DescribeInstances(ctx, backend.Scope{Account: account}, resource.InstanceQuery{
			IDs: []resource.InstanceID{id}, Page: resource.PageRequest{Size: 50},
		})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("describe %s: %v %+v", id, err, page.Items)
		}
		return page.Items[0]
	}
	type placed struct {
		subnet resource.SubnetID
		vpc    resource.VpcID
	}
	check := func(what string, inst resource.Instance, want ...placed) {
		t.Helper()
		nics := inst.NetworkInterfaces
		if len(nics) != len(want) {
			t.Fatalf("%s: interfaces %+v, want %+v", what, nics, want)
		}
		for i, w := range want {
			if nics[i].DeviceIndex != i || nics[i].SubnetID != w.subnet || nics[i].VpcID != w.vpc || nics[i].PrivateIP == "" {
				t.Fatalf("%s: interface %d is %+v, want %+v with an address", what, i, nics[i], w)
			}
		}
		if inst.SubnetID != nics[0].SubnetID || inst.VpcID != nics[0].VpcID || inst.PrivateIP != nics[0].PrivateIP {
			t.Fatalf("%s: instance on %s %s %s, want its device 0 interface %+v",
				what, inst.SubnetID, inst.VpcID, inst.PrivateIP, nics[0])
		}
	}
	subnet := func(id resource.SubnetID) placed {
		t.Helper()
		page, err := set.Network.DescribeSubnets(ctx, backend.Scope{Account: owner}, resource.SubnetQuery{
			IDs: []resource.SubnetID{id}, Page: resource.PageRequest{Size: 50},
		})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("subnet %s: %v %+v", id, err, page.Items)
		}
		return placed{id, page.Items[0].VpcID}
	}
	onOverlay, onDirect := subnet(overlay), placed{direct, resource.DirectVpcID()}

	mixed := mut(owner, "mixed")
	first, err := launch(mixed,
		resource.NetworkInterfaceSpec{DeviceIndex: 1, SubnetID: direct},
		resource.NetworkInterfaceSpec{DeviceIndex: 0, SubnetID: overlay})
	if err != nil {
		t.Fatalf("overlay primary with a direct secondary: %v", err)
	}
	id := first.Items[0].ID
	again, err := launch(mixed,
		resource.NetworkInterfaceSpec{DeviceIndex: 1, SubnetID: direct},
		resource.NetworkInterfaceSpec{DeviceIndex: 0, SubnetID: overlay})
	if err != nil || len(again.Items) != 1 || again.Items[0].ID != id || again.Operation.ID != first.Operation.ID {
		t.Fatalf("retry of a two-interface launch: %v %+v, want instance %s", err, again.Items, id)
	}
	if _, err := set.Compute.GetOperation(ctx, mixed.Scope, first.Operation.ID); err != nil {
		t.Fatal(err)
	}
	check("mixed launch", read(set, owner, id), onOverlay, onDirect)
	check("mixed launch on a new client", read(newSet(), owner, id), onOverlay, onDirect)

	ids := []resource.InstanceID{id}
	stop, err := set.Compute.StopInstances(ctx, mut(owner, "stop"), resource.StopInstancesRequest{IDs: ids})
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := set.Compute.GetOperation(ctx, mixed.Scope, stop.Operation.ID); err != nil {
		t.Fatal(err)
	}
	start, err := set.Compute.StartInstances(ctx, mut(owner, "start"), resource.StartInstancesRequest{IDs: ids})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := set.Compute.GetOperation(ctx, mixed.Scope, start.Operation.ID); err != nil {
		t.Fatal(err)
	}
	check("mixed launch after a stop and start", read(set, owner, id), onOverlay, onDirect)

	second, err := set.Network.CreateSubnet(ctx, mut(owner, "second"), resource.CreateSubnetRequest{Cidr: "10.8.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Network.GetOperation(ctx, mixed.Scope, second.Operation.ID); err != nil {
		t.Fatal(err)
	}
	onSecond := subnet(second.Items[0].ID)
	behind, err := launch(mut(owner, "direct-primary"),
		resource.NetworkInterfaceSpec{DeviceIndex: 0, SubnetID: direct},
		resource.NetworkInterfaceSpec{DeviceIndex: 1, SubnetID: onSecond.subnet})
	if err != nil {
		t.Fatalf("direct primary with an overlay secondary: %v", err)
	}
	check("direct primary launch", read(set, owner, behind.Items[0].ID), onDirect, onSecond)
	_, err = set.Network.DeleteSubnet(ctx, mut(owner, "del-second"), resource.DeleteSubnetRequest{ID: onSecond.subnet})
	if resource.CodeOf(err) != resource.CodeConflict {
		t.Fatalf("delete of a subnet only a secondary interface uses: %v, want Conflict", err)
	}

	only, err := launch(mut(other, "direct-only"), resource.NetworkInterfaceSpec{DeviceIndex: 0, SubnetID: direct})
	if err != nil {
		t.Fatalf("direct primary in another account: %v", err)
	}
	check("direct-only launch", read(set, other, only.Items[0].ID), onDirect)

	if _, err := launch(mut(other, "foreign"),
		resource.NetworkInterfaceSpec{DeviceIndex: 0, SubnetID: direct},
		resource.NetworkInterfaceSpec{DeviceIndex: 1, SubnetID: overlay},
	); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("a secondary interface on another account's subnet: %v, want NotFound", err)
	}
	missing := parse[resource.SubnetID](t, "subnet-direct-nope")
	if _, err := launch(mut(other, "missing"),
		resource.NetworkInterfaceSpec{DeviceIndex: 0, SubnetID: direct},
		resource.NetworkInterfaceSpec{DeviceIndex: 1, SubnetID: missing},
	); resource.AsError(err).Kind != resource.KindSubnet || resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("a missing direct subnet: %v, want a subnet NotFound", err)
	}
	all, err := set.Compute.DescribeInstances(ctx, backend.Scope{Account: other}, resource.InstanceQuery{
		Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(all.Items) != 1 {
		t.Fatalf("refused launches left instances: %v %+v", err, all.Items)
	}

	associate := func(account resource.AccountID, key string, inst resource.InstanceID) (resource.AddressID, error) {
		t.Helper()
		eip, err := set.Network.AllocateAddress(ctx, mut(account, key), resource.AllocateAddressRequest{Domain: "vpc"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = set.Network.AssociateAddress(ctx, mut(account, key+"-assoc"), resource.AssociateAddressRequest{
			ID: eip.Items[0].ID, InstanceID: inst,
		})
		return eip.Items[0].ID, err
	}
	for _, c := range []struct {
		account resource.AccountID
		key     string
		inst    resource.InstanceID
	}{{owner, "eip-direct-primary", behind.Items[0].ID}, {other, "eip-direct-only", only.Items[0].ID}} {
		eip, err := associate(c.account, c.key, c.inst)
		if !resource.IsInvalidCombination(resource.AsError(err)) {
			t.Fatalf("%s: elastic IP on a direct primary interface: %v, want InvalidParameterCombination", c.key, err)
		}
		page, err := set.Network.DescribeAddresses(ctx, backend.Scope{Account: c.account}, resource.AddressQuery{
			IDs: []resource.AddressID{eip}, Page: resource.PageRequest{Size: 50},
		})
		if err != nil || len(page.Items) != 1 || !page.Items[0].InstanceID.IsZero() {
			t.Fatalf("%s: a refused association stuck: %v %+v", c.key, err, page.Items)
		}
	}
	if _, err := associate(owner, "eip-overlay-primary", id); err != nil {
		t.Fatalf("elastic IP on an overlay primary with a direct secondary: %v", err)
	}
}

// checkDirectVisible checks that account reads the direct subnet as vws-network
// serves it, in a listing and by id.
func checkDirectVisible(
	ctx context.Context, t *testing.T, set backend.Set, account resource.AccountID, direct resource.SubnetID,
) {
	t.Helper()
	scope := backend.Scope{Account: account}
	wantTags := map[string]string{resource.DirectNetworkTagKey: resource.DirectNetworkTagValue}
	same := func(got resource.Subnet) bool {
		return got.ID == direct && got.OwnerID == account && got.VpcID == resource.DirectVpcID() &&
			got.Cidr == DirectCidr && got.State == resource.SubnetAvailable && got.Zone == resource.ZoneName &&
			!got.MapPublicIPOnLaunch && maps.Equal(got.Tags, wantTags)
	}
	all, err := set.Network.DescribeSubnets(ctx, scope, resource.SubnetQuery{Page: resource.PageRequest{Size: 50}})
	if err != nil {
		t.Fatal(err)
	}
	listed := false
	for _, sub := range all.Items {
		if sub.ID == direct {
			listed = same(sub)
		}
	}
	if !listed {
		t.Fatalf("account %s listing %+v, want %s in vpc-direct tagged %v", account, all.Items, direct, wantTags)
	}
	one, err := set.Network.DescribeSubnets(ctx, scope, resource.SubnetQuery{
		IDs: []resource.SubnetID{direct}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(one.Items) != 1 || !same(one.Items[0]) {
		t.Fatalf("account %s by id: %v %+v, want %s in vpc-direct tagged %v", account, err, one.Items, direct, wantTags)
	}
}

func parse[T any, PT interface {
	*T
	UnmarshalText([]byte) error
}](t *testing.T, s string) T {
	t.Helper()
	v, err := resource.Parse[T, PT](s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
