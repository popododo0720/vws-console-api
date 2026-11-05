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
