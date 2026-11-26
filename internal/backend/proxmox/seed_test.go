package proxmox

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// seedScenario is a mutation token that passes the seed_storage check: the
// storage seed with iso content on both nodes, Datastore.AllocateTemplate
// and Datastore.Audit on /storage/seed only, and VM.Config.CDROM on the
// managed pool.
func seedScenario() pvefake.Scenario {
	s := scenario()
	s.Nodes = append(s.Nodes, pvefake.Node{Name: "pve2"})
	s.Pools = []string{"managed"}
	s.Storages = append(s.Storages,
		pvefake.Storage{Node: "pve1", Name: "seed", Types: "iso,vztmpl"},
		pvefake.Storage{Node: "pve2", Name: "seed", Types: "vztmpl,iso"},
	)
	s.Roles = append(s.Roles,
		pvefake.Role{ID: "VWSSeed", Privs: []string{"Datastore.AllocateTemplate", "Datastore.Audit"}},
		pvefake.Role{ID: "VWSPool", Privs: []string{"VM.Audit", "Pool.Audit", "VM.Config.CDROM"}},
	)
	s.Tokens[0].ACL = append(s.Tokens[0].ACL,
		pvefake.ACE{Path: "/storage/seed", Role: "VWSSeed"},
		pvefake.ACE{Path: "/pool/managed", Role: "VWSPool"},
	)
	return s
}

func seedConfig(t *testing.T) RegionConfig {
	t.Helper()
	return RegionConfig{
		SeedStorage: "seed", StateDir: t.TempDir(), Pools: map[string]string{"123456789012": "managed"},
		Subnets: map[string]SubnetConfig{
			"vmbr0": {CIDR: "192.0.2.0/24", Gateway: "192.0.2.1", Nameservers: []string{"192.0.2.53"}},
			"vmbr1": {Mode: "static", Nameservers: []string{"10.0.0.2", "10.0.0.3", "10.0.0.4"}},
			"vmbr2": {Mode: "dhcp"},
		},
	}
}

// Each seed_storage rule refuses the registration on its own, as the check
// seed_storage; a region without seed_storage, or a read_only one, takes
// none of them.
func TestSeedStorageSelfCheck(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*pvefake.Scenario, *RegionConfig)
		want string
	}{
		{"passes", func(*pvefake.Scenario, *RegionConfig) {}, ""},
		{"no state directory", func(_ *pvefake.Scenario, c *RegionConfig) { c.StateDir = "" }, "state directory"},
		{"unknown storage", func(_ *pvefake.Scenario, c *RegionConfig) { c.SeedStorage = "other" }, `unknown seed_storage`},
		{"one row without iso", func(s *pvefake.Scenario, _ *RegionConfig) {
			s.Storages[len(s.Storages)-1].Types = "images,isos"
		}, "on pve2 has no iso content"},
		{"no AllocateTemplate", func(s *pvefake.Scenario, _ *RegionConfig) {
			s.Roles[len(s.Roles)-2].Privs = []string{"Datastore.Audit"}
		}, "lacks Datastore.AllocateTemplate on /storage/seed"},
		{"no Audit", func(s *pvefake.Scenario, _ *RegionConfig) {
			s.Roles[len(s.Roles)-2].Privs = []string{"Datastore.AllocateTemplate"}
		}, "or the token lacks Datastore.Audit on it"},
		{"AllocateTemplate elsewhere", func(s *pvefake.Scenario, _ *RegionConfig) {
			s.Tokens[0].ACL = append(s.Tokens[0].ACL, pvefake.ACE{Path: "/storage/local", Role: "VWSSeed"})
		}, "holds Datastore.AllocateTemplate on /storage/local"},
		{"pool without CDROM", func(s *pvefake.Scenario, _ *RegionConfig) {
			s.Roles[len(s.Roles)-1].Privs = []string{"VM.Audit", "Pool.Audit"}
		}, "lacks VM.Config.CDROM on /pool/managed"},
		{"static subnet without nameservers", func(_ *pvefake.Scenario, c *RegionConfig) {
			c.Subnets["vmbr0"] = SubnetConfig{CIDR: "192.0.2.0/24"}
		}, "subnets.vmbr0: a static subnet needs 1 to 3 nameservers"},
		{"four nameservers", func(_ *pvefake.Scenario, c *RegionConfig) {
			c.Subnets["vmbr1"] = SubnetConfig{
				Mode: "static", Nameservers: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"},
			}
		}, "subnets.vmbr1: a static subnet needs 1 to 3 nameservers"},
		{"IPv6 nameserver", func(_ *pvefake.Scenario, c *RegionConfig) {
			c.Subnets["vmbr1"] = SubnetConfig{Mode: "static", Nameservers: []string{"2001:db8::53"}}
		}, `nameserver "2001:db8::53" is not an IPv4 address`},
		{"unspecified nameserver", func(_ *pvefake.Scenario, c *RegionConfig) {
			c.Subnets["vmbr1"] = SubnetConfig{Mode: "static", Nameservers: []string{"0.0.0.0"}}
		}, "is not an IPv4 address"},
		{"DHCP subnet with nameservers", func(_ *pvefake.Scenario, c *RegionConfig) {
			c.Subnets["vmbr2"] = SubnetConfig{Mode: "dhcp", Nameservers: []string{"10.0.0.2"}}
		}, "subnets.vmbr2: nameservers are for static subnets only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, cfg := seedScenario(), seedConfig(t)
			tc.edit(&s, &cfg)
			c, _ := serve(t, s)
			b, err := New(t.Context(), c, registration(), cfg)
			if tc.want == "" {
				if err != nil || b == nil {
					t.Fatalf("New = %v", err)
				}
				return
			}
			var check *selfCheckError
			if b != nil || !errors.As(err, &check) || check.check != "seed_storage" ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New = %v, want the seed_storage check naming %q", err, tc.want)
			}
		})
	}
	// Without seed_storage, or read_only, the seed rules do not apply: a
	// token without any seed grant and subnets without nameservers pass.
	for _, cfg := range []RegionConfig{
		{Subnets: map[string]SubnetConfig{"vmbr0": {CIDR: "192.0.2.0/24"}}},
		{ReadOnly: true, SeedStorage: "seed", Subnets: map[string]SubnetConfig{"vmbr0": {}}},
	} {
		c, _ := serve(t, scenario())
		if b, err := New(t.Context(), c, registration(), cfg); err != nil || b == nil {
			t.Fatalf("New(%+v) = %v", cfg, err)
		}
	}
}

// With seed_storage set, a node without that storage is never a candidate.
func TestSchedulePlacesOnlyOnNodesWithTheSeedStorage(t *testing.T) {
	rows := append(placementSnapshot("pve1", "pve2", "pve3"),
		pveclient.ClusterResource{Type: "storage", Node: "pve2", Storage: "seed"},
		pveclient.ClusterResource{Type: "qemu", Node: "pve3", Storage: "seed"},
	)
	region := backend.ProxmoxRegion{Name: "pve-test-1"}
	req := placementRequest()
	req.Count = 4
	spread, err := Schedule(rows, region, req, SchedulerConfig{})
	if err != nil || len(spread) != 4 || spread[0].Node == spread[1].Node {
		t.Fatalf("without seed_storage: %+v %v", spread, err)
	}
	req.SeedStorage = "seed"
	plan, err := Schedule(rows, region, req, SchedulerConfig{})
	if err != nil || len(plan) != 4 {
		t.Fatalf("with seed_storage: %+v %v", plan, err)
	}
	for _, p := range plan {
		if p.Node != "pve2" || p.Storage != "local-lvm" {
			t.Fatalf("placed on %+v, want pve2 with the root storage", p)
		}
	}
	req.SeedStorage = "missing"
	_, err = Schedule(rows, region, req, SchedulerConfig{})
	if !resource.IsInsufficientInstanceCapacity(resource.AsError(err)) {
		t.Fatalf("no node with the seed storage: %v", err)
	}
}

// Apart from placement, a launch in a region with seed_storage sends PVE
// exactly the requests it sends without it, and its clones go only to the
// nodes that have the seed storage.
func TestRunInstancesWithSeedStorageLaunchesAsBefore(t *testing.T) {
	launch := func(seed string, nodes ...string) ([]string, []string) {
		t.Helper()
		w, m, req := launchBackend(t, true, func(s *pvefake.Scenario) {
			for _, node := range nodes {
				s.Storages = append(s.Storages, pvefake.Storage{Node: node, Name: "seed", Types: "iso"})
			}
		})
		w.b.cfg.SeedStorage = seed
		req.Count = 4
		before := len(w.f.Requests())
		if _, err := w.b.RunInstances(t.Context(), m, req); err != nil {
			t.Fatal(err)
		}
		var targets []string
		for _, form := range w.forms {
			targets = append(targets, form.Get("target"))
		}
		return w.f.Requests()[before:], targets
	}
	plain, plainTargets := launch("", "pve1", "pve2")
	seeded, seededTargets := launch("seed", "pve1", "pve2")
	if !reflect.DeepEqual(plain, seeded) || !reflect.DeepEqual(plainTargets, seededTargets) {
		t.Fatalf("seed_storage changed the launch:\n%v\n%v", plain, seeded)
	}
	if !strings.Contains(strings.Join(plainTargets, ","), "pve1") {
		t.Fatalf("the launch never used pve1, so the next case proves nothing: %v", plainTargets)
	}
	_, targets := launch("seed", "pve2")
	for _, target := range targets {
		if target != "pve2" {
			t.Fatalf("a clone went to %q without the seed storage: %v", target, targets)
		}
	}
}
