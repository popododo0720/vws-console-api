package backendtest

import (
	"context"
	"slices"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Option adjusts Run for a kind of harness.
type Option func(*options)

type options struct {
	seeded bool
}

// SeededInventory declares that every set the harness returns reopens the same
// pre-seeded upstream inventory, as a read-only backend over a fixed fake does.
// Run then compares IDs across a recreated backend, and a supported read with
// nothing seeded fails.
func SeededInventory() Option {
	return func(o *options) { o.seeded = true }
}

// idStability compares every supported Describe ID across all pages of first
// and second. Without a seeded harness second is first, and the group checks
// that repeated reads list the same IDs.
func idStability(
	t *testing.T, first, second backend.Set, caps resource.RegionCapabilities, scope backend.Scope, seeded bool,
) {
	t.Helper()
	t.Run("Instances", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeInstances, scope, seeded,
			first.Compute.DescribeInstances, second.Compute.DescribeInstances,
			func(p resource.PageRequest) resource.InstanceQuery { return resource.InstanceQuery{Page: p} })
	})
	t.Run("Images", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeImages, scope, seeded,
			first.Compute.DescribeImages, second.Compute.DescribeImages,
			func(p resource.PageRequest) resource.ImageQuery { return resource.ImageQuery{Page: p} })
	})
	t.Run("Volumes", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeVolumes, scope, seeded,
			first.Compute.DescribeVolumes, second.Compute.DescribeVolumes,
			func(p resource.PageRequest) resource.VolumeQuery { return resource.VolumeQuery{Page: p} })
	})
	t.Run("Snapshots", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeSnapshots, scope, seeded,
			first.Compute.DescribeSnapshots, second.Compute.DescribeSnapshots,
			func(p resource.PageRequest) resource.SnapshotQuery { return resource.SnapshotQuery{Page: p} })
	})
	t.Run("KeyPairs", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeKeyPairs, scope, seeded,
			first.Compute.DescribeKeyPairs, second.Compute.DescribeKeyPairs,
			func(p resource.PageRequest) resource.KeyPairQuery { return resource.KeyPairQuery{Page: p} })
	})
	t.Run("Vpcs", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeVpcs, scope, seeded,
			first.Network.DescribeVpcs, second.Network.DescribeVpcs,
			func(p resource.PageRequest) resource.VpcQuery { return resource.VpcQuery{Page: p} })
	})
	t.Run("Subnets", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeSubnets, scope, seeded,
			first.Network.DescribeSubnets, second.Network.DescribeSubnets,
			func(p resource.PageRequest) resource.SubnetQuery { return resource.SubnetQuery{Page: p} })
	})
	t.Run("SecurityGroups", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeSecurityGroups, scope, seeded,
			first.Network.DescribeSecurityGroups, second.Network.DescribeSecurityGroups,
			func(p resource.PageRequest) resource.SecurityGroupQuery { return resource.SecurityGroupQuery{Page: p} })
	})
	t.Run("Addresses", func(t *testing.T) {
		stableInventory(t, caps, resource.ReadDescribeAddresses, scope, seeded,
			first.Network.DescribeAddresses, second.Network.DescribeAddresses,
			func(p resource.PageRequest) resource.AddressQuery { return resource.AddressQuery{Page: p} })
	})
}

func stableInventory[Q any, T interface{ Identity() string }](
	t *testing.T, caps resource.RegionCapabilities, action resource.ReadAction, scope backend.Scope, seeded bool,
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
	before := ids(first)
	requireInventory(t, action, len(before), seeded)
	if after := ids(second); !slices.Equal(before, after) {
		t.Fatalf("IDs changed between reads:\nbefore %v\nafter  %v", before, after)
	}
}

// readTenancy checks instances, volumes and snapshots without mutations: the
// other account lists only its own resources and none of the owner's, and
// reading an owner's ID as the other account is NotFound or an empty page.
func readTenancy(
	t *testing.T, set backend.Set, caps resource.RegionCapabilities, owner, other backend.Scope, seeded bool,
) {
	t.Helper()
	t.Run("Instances", func(t *testing.T) {
		privateInventory(t, caps, resource.ReadDescribeInstances, owner, other, seeded, set.Compute.DescribeInstances,
			func(ids []resource.InstanceID, p resource.PageRequest) resource.InstanceQuery {
				return resource.InstanceQuery{IDs: ids, Page: p}
			}, func(v resource.Instance) resource.InstanceID { return v.ID })
	})
	t.Run("Volumes", func(t *testing.T) {
		privateInventory(t, caps, resource.ReadDescribeVolumes, owner, other, seeded, set.Compute.DescribeVolumes,
			func(ids []resource.VolumeID, p resource.PageRequest) resource.VolumeQuery {
				return resource.VolumeQuery{IDs: ids, Page: p}
			}, func(v resource.Volume) resource.VolumeID { return v.ID })
	})
	t.Run("Snapshots", func(t *testing.T) {
		privateInventory(t, caps, resource.ReadDescribeSnapshots, owner, other, seeded, set.Compute.DescribeSnapshots,
			func(ids []resource.SnapshotID, p resource.PageRequest) resource.SnapshotQuery {
				return resource.SnapshotQuery{IDs: ids, Page: p}
			}, func(v resource.Snapshot) resource.SnapshotID { return v.ID })
	})
}

func privateInventory[Q, ID any, T interface {
	Identity() string
	Owner() resource.AccountID
}](
	t *testing.T, caps resource.RegionCapabilities, action resource.ReadAction, owner, other backend.Scope, seeded bool,
	call func(context.Context, backend.Scope, Q) (resource.Page[T], error),
	query func([]ID, resource.PageRequest) Q, id func(T) ID,
) {
	t.Helper()
	requireCapabilities(t, caps, nil, []resource.ReadAction{action})
	list := func(p resource.PageRequest) Q { return query(nil, p) }
	items := inventoryPages(t, owner, call, list)
	requireInventory(t, action, len(items), seeded)
	owned := map[string]bool{}
	for _, item := range items {
		if item.Owner() != owner.Account {
			t.Fatalf("%s owner = %s, want %s", item.Identity(), item.Owner(), owner.Account)
		}
		owned[item.Identity()] = true
	}
	for _, item := range inventoryPages(t, other, call, list) {
		if owned[item.Identity()] || item.Owner() != other.Account {
			t.Fatalf("other account listed %s owned by %s", item.Identity(), item.Owner())
		}
	}
	for _, item := range items {
		page, err := call(t.Context(), other, query([]ID{id(item)}, resource.PageRequest{Size: 1}))
		if err != nil && resource.CodeOf(err) != resource.CodeNotFound {
			t.Fatalf("other account reading %s: %v", item.Identity(), err)
		}
		if len(page.Items) != 0 || page.NextToken != "" {
			t.Fatalf("other account read %s: %+v", item.Identity(), page)
		}
	}
}

// requireInventory fails a seeded harness with nothing to compare, so a
// seeding mistake cannot pass as stable or private.
func requireInventory(t *testing.T, action resource.ReadAction, n int, seeded bool) {
	t.Helper()
	if n == 0 && seeded {
		t.Fatalf("%s: seeded harness lists nothing", action.CapabilityKey())
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
