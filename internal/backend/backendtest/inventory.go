package backendtest

import (
	"context"
	"slices"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// IDStability reopens the same seeded inventory and compares every supported
// Describe ID across all pages. reopen must recreate the backend, preserving
// its upstream state. Each supported read needs at least one seeded resource.
func IDStability(t *testing.T, reopen Harness, caps resource.RegionCapabilities, scope backend.Scope) {
	t.Helper()
	first, second := reopen(), reopen()
	t.Run("Instances", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeInstances, scope,
			first.Compute.DescribeInstances, second.Compute.DescribeInstances,
			func(p resource.PageRequest) resource.InstanceQuery { return resource.InstanceQuery{Page: p} })
	})
	t.Run("Images", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeImages, scope,
			first.Compute.DescribeImages, second.Compute.DescribeImages,
			func(p resource.PageRequest) resource.ImageQuery { return resource.ImageQuery{Page: p} })
	})
	t.Run("Volumes", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeVolumes, scope,
			first.Compute.DescribeVolumes, second.Compute.DescribeVolumes,
			func(p resource.PageRequest) resource.VolumeQuery { return resource.VolumeQuery{Page: p} })
	})
	t.Run("Snapshots", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeSnapshots, scope,
			first.Compute.DescribeSnapshots, second.Compute.DescribeSnapshots,
			func(p resource.PageRequest) resource.SnapshotQuery { return resource.SnapshotQuery{Page: p} })
	})
	t.Run("KeyPairs", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeKeyPairs, scope,
			first.Compute.DescribeKeyPairs, second.Compute.DescribeKeyPairs,
			func(p resource.PageRequest) resource.KeyPairQuery { return resource.KeyPairQuery{Page: p} })
	})
	t.Run("Vpcs", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeVpcs, scope,
			first.Network.DescribeVpcs, second.Network.DescribeVpcs,
			func(p resource.PageRequest) resource.VpcQuery { return resource.VpcQuery{Page: p} })
	})
	t.Run("Subnets", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeSubnets, scope,
			first.Network.DescribeSubnets, second.Network.DescribeSubnets,
			func(p resource.PageRequest) resource.SubnetQuery { return resource.SubnetQuery{Page: p} })
	})
	t.Run("SecurityGroups", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeSecurityGroups, scope,
			first.Network.DescribeSecurityGroups, second.Network.DescribeSecurityGroups,
			func(p resource.PageRequest) resource.SecurityGroupQuery { return resource.SecurityGroupQuery{Page: p} })
	})
	t.Run("Addresses", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeAddresses, scope,
			first.Network.DescribeAddresses, second.Network.DescribeAddresses,
			func(p resource.PageRequest) resource.AddressQuery { return resource.AddressQuery{Page: p} })
	})
}

func stableInventory[Q any, T interface{ Identity() string }](
	t *testing.T, caps resource.RegionCapabilities, action resource.ReadAction, scope backend.Scope,
	first, second func(context.Context, backend.Scope, Q) (resource.Page[T], error),
	query func(resource.PageRequest) Q,
) {
	t.Helper()
	requireCapabilities(t, caps, nil, []resource.ReadAction{action})
	ids := func(call func(context.Context, backend.Scope, Q) (resource.Page[T], error)) []string {
		items := inventoryPages(t, scope, call, query)
		var out []string
		for _, item := range items {
			out = append(out, item.Identity())
		}
		slices.Sort(out)
		return out
	}
	before, after := ids(first), ids(second)
	if len(before) == 0 {
		t.Fatal("id stability needs seeded inventory")
	}
	if !slices.Equal(before, after) {
		t.Fatalf("restart changed IDs:\nbefore %v\nafter  %v", before, after)
	}
}

// ReadTenancy checks seeded instances, volumes and snapshots without mutations.
// other must have no inventory: its list must be empty and each owner's ID must
// return NotFound or an empty page.
func ReadTenancy(t *testing.T, set backend.Set, caps resource.RegionCapabilities, owner, other backend.Scope) {
	t.Helper()
	t.Run("Instances", func(t *testing.T) {
		privateInventory(t, caps, resource.ReadDescribeInstances, owner, other, set.Compute.DescribeInstances,
			func(ids []resource.InstanceID, p resource.PageRequest) resource.InstanceQuery {
				return resource.InstanceQuery{IDs: ids, Page: p}
			}, func(v resource.Instance) resource.InstanceID { return v.ID })
	})
	t.Run("Volumes", func(t *testing.T) {
		privateInventory(t, caps, resource.ReadDescribeVolumes, owner, other, set.Compute.DescribeVolumes,
			func(ids []resource.VolumeID, p resource.PageRequest) resource.VolumeQuery {
				return resource.VolumeQuery{IDs: ids, Page: p}
			}, func(v resource.Volume) resource.VolumeID { return v.ID })
	})
	t.Run("Snapshots", func(t *testing.T) {
		privateInventory(t, caps, resource.ReadDescribeSnapshots, owner, other, set.Compute.DescribeSnapshots,
			func(ids []resource.SnapshotID, p resource.PageRequest) resource.SnapshotQuery {
				return resource.SnapshotQuery{IDs: ids, Page: p}
			}, func(v resource.Snapshot) resource.SnapshotID { return v.ID })
	})
}

func privateInventory[Q, ID any, T interface {
	Identity() string
	Owner() resource.AccountID
}](
	t *testing.T, caps resource.RegionCapabilities, action resource.ReadAction, owner, other backend.Scope,
	call func(context.Context, backend.Scope, Q) (resource.Page[T], error),
	query func([]ID, resource.PageRequest) Q, id func(T) ID,
) {
	t.Helper()
	requireCapabilities(t, caps, nil, []resource.ReadAction{action})
	list := func(p resource.PageRequest) Q { return query(nil, p) }
	items := inventoryPages(t, owner, call, list)
	if len(items) == 0 {
		t.Fatal("tenancy needs seeded inventory")
	}
	if got := inventoryPages(t, other, call, list); len(got) != 0 {
		t.Fatalf("other account listed %d resources", len(got))
	}
	for _, item := range items {
		if item.Owner() != owner.Account {
			t.Fatalf("%s owner = %s, want %s", item.Identity(), item.Owner(), owner.Account)
		}
		page, err := call(t.Context(), other, query([]ID{id(item)}, resource.PageRequest{Size: 1}))
		if err != nil && resource.CodeOf(err) != resource.CodeNotFound {
			t.Fatalf("other account reading %s: %v", item.Identity(), err)
		}
		if len(page.Items) != 0 || page.NextToken != "" {
			t.Fatalf("other account read %s: %+v", item.Identity(), page)
		}
	}
}

func inventoryPages[Q any, T interface{ Identity() string }](
	t *testing.T, scope backend.Scope,
	call func(context.Context, backend.Scope, Q) (resource.Page[T], error),
	query func(resource.PageRequest) Q,
) []T {
	t.Helper()
	var items []T
	seen := map[string]bool{}
	request := resource.PageRequest{Size: 1}
	for {
		page, err := call(t.Context(), scope, query(request))
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, page.Items...)
		if page.NextToken == "" {
			return items
		}
		if seen[page.NextToken] {
			t.Fatalf("inventory repeated page token %q", page.NextToken)
		}
		seen[page.NextToken] = true
		request.Token = page.NextToken
	}
}
