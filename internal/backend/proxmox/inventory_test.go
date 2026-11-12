package proxmox

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func inventoryScenario() pvefake.Scenario {
	s := scenario()
	s.Roles[0].Privs = append(s.Roles[0].Privs, "Pool.Audit")
	s.VMs = []pvefake.VM{{VMID: 100, Node: "pve1", Name: "manual", Pool: "123456789012", Status: "running"}}
	s.VMs[0].Config = map[string]string{
		"smbios1": "uuid=5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10",
		"meta":    "creation-qemu=9.2,ctime=1700000000", "cores": "1", "sockets": "1", "memory": "1024",
	}
	return s
}

func inventoryScope() backend.Scope {
	account, _ := resource.Parse[resource.AccountID]("123456789012")
	return backend.Scope{Account: account}
}

func TestInventoryReservationSurvivesRestart(t *testing.T) {
	for _, uuid := range []string{"5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10", ""} {
		t.Run(uuid, func(t *testing.T) {
			var want resource.ReservationID
			for range 2 {
				s := inventoryScenario()
				s.VMs[0].Config["smbios1"] = "uuid=" + uuid
				client, _ := serve(t, s)
				for range 2 {
					b, err := New(t.Context(), client, registration(), RegionConfig{})
					if err != nil {
						t.Fatal(err)
					}
					for range 2 {
						page, err := b.DescribeInstances(t.Context(), inventoryScope(), resource.InstanceQuery{})
						if err != nil || len(page.Items) != 1 || page.Items[0].ReservationID.IsZero() {
							t.Fatalf("reservation after restart/re-run: %+v, %v", page, err)
						}
						got := page.Items[0].ReservationID
						if !want.IsZero() && got != want {
							t.Fatalf("reservation changed: got %s, want %s", got, want)
						}
						want = got
					}
				}
			}
		})
	}
}

func TestInventoryInstanceFields(t *testing.T) {
	s := inventoryScenario()
	c, _ := serve(t, s)
	reg := registration()
	reg.Region.Zones = []backend.Zone{{Letter: "b", Nodes: []string{"pve1"}}}
	b, err := New(t.Context(), c, reg, RegionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	page, err := b.DescribeInstances(t.Context(), inventoryScope(), resource.InstanceQuery{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("untagged VM inventory=%+v error=%v", page, err)
	}
	ids, _ := NewIDs("test")
	id, _, _ := ids.Instance(VM{UUID: "5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10"})
	reservation, err := ids.Reservation(id.String())
	if err != nil {
		t.Fatal(err)
	}
	unknown, _ := ids.UnknownImage()
	got := page.Items[0]
	if got.ID != id || got.ReservationID != reservation || got.ImageID != unknown ||
		got.OwnerID != inventoryScope().Account ||
		got.State != resource.InstanceRunning || got.InstanceType != "vws.small" || len(got.Tags) != 0 ||
		got.Zone != "pve-test-1b" || got.LaunchTime.Unix() != 1700000000 {
		t.Fatalf("instance=%+v", got)
	}
	for range 2 {
		fresh, err := New(t.Context(), c, reg, RegionConfig{})
		if err != nil {
			t.Fatal(err)
		}
		again, err := fresh.DescribeInstances(t.Context(), inventoryScope(), resource.InstanceQuery{})
		if err != nil || !reflect.DeepEqual(page, again) {
			t.Fatalf("restart/re-run=%+v error=%v", again, err)
		}
	}
	for _, tc := range []struct {
		uuid, lock, qmp, status string
		want                    resource.InstanceState
	}{
		{"", "", "", "stopped", resource.InstanceStopped},
		{"5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10", "clone", "", "stopped", resource.InstancePending},
		{"5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10", "create", "", "running", resource.InstancePending},
		{"", "", "paused", "running", resource.InstancePending},
		{"", "", "prelaunch", "running", resource.InstancePending},
	} {
		t.Run(tc.lock+tc.qmp+tc.status, func(t *testing.T) {
			cfg := pveclient.VMConfig{
				Lock: tc.lock, QMPStatus: tc.qmp, Meta: "ctime=1700000000",
				Description: "vws:uuid 5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10\nvws:tags {\"long\":\"value\"}",
				Tags:        "vws.t.+name.web;vws.ami.0123456789abcdef0;vws.k.secret",
			}
			vm := inventoryVM{pveclient.ClusterResource{VMID: 100, Node: "pve1", Status: tc.status}}
			inst, err := b.instance(t.Context(), ids, vm, cfg)
			expect, _, _ := ids.Instance(VM{UUID: tc.uuid, VMID: 100, Ctime: "1700000000"})
			reservation, reservationErr := ids.Reservation(expect.String())
			if reservationErr != nil {
				t.Fatal(reservationErr)
			}
			if err != nil || inst.ID != expect || inst.State != tc.want || len(inst.Tags) != 2 ||
				inst.ReservationID != reservation || inst.Tags["Name"] != "web" ||
				inst.ImageID.String() != "ami-0123456789abcdef0" {
				t.Fatalf("mapped=%+v error=%v", inst, err)
			}
		})
	}
	s.VMs = append(s.VMs, pvefake.VM{
		VMID: 101, Node: "pve1", Pool: "123456789012", Config: map[string]string{"smbios1": "uuid=bad"},
	})
	bad, _ := networkBackend(t, s, RegionConfig{})
	valid, err := bad.DescribeInstances(t.Context(), inventoryScope(), resource.InstanceQuery{})
	if err != nil || len(valid.Items) != 1 {
		t.Fatalf("malformed VM failed listing: %+v %v", valid, err)
	}
}

func TestInventoryPoolMove(t *testing.T) {
	s := inventoryScenario()
	s.VMs[0].Pool = "parent/child"
	b, f := networkBackend(t, s, RegionConfig{
		DefaultProject: "123456789012", Pools: map[string]string{"123456789012": "parent/child"},
	})
	foreign, _ := resource.Parse[resource.AccountID]("999999999999")
	for _, pool := range []string{"parent/child", "999999999999", ""} {
		if err := f.MoveVM(100, pool); err != nil {
			t.Fatal(err)
		}
		for _, scope := range []backend.Scope{inventoryScope(), {Account: foreign}} {
			page, err := b.DescribeInstances(t.Context(), scope, resource.InstanceQuery{})
			want := 0
			if (scope.Account == foreign) == (pool == "999999999999") {
				want = 1
			}
			if err != nil || len(page.Items) != want {
				t.Fatalf("pool=%q page=%+v error=%v want=%d", pool, page, err, want)
			}
		}
	}
	s.Roles[0].Privs = slices.DeleteFunc(s.Roles[0].Privs, func(p string) bool { return p == "Pool.Audit" })
	limited, _ := networkBackend(t, s, RegionConfig{DefaultProject: "123456789012"})
	_, err := limited.DescribeInstances(t.Context(), inventoryScope(), resource.InstanceQuery{})
	if resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Fatalf("pool names hidden by PVE must not expose foreign VMs: %v", err)
	}
}

func TestInventoryTemplatesAndHolders(t *testing.T) {
	s := inventoryScenario()
	vm := s.VMs[0]
	vm.VMID, vm.Template = 101, true
	s.VMs = append(s.VMs, vm, pvefake.VM{VMID: 105, Node: "pve1", Pool: "123456789012", Tags: "vws.holder"})
	b, _ := networkBackend(t, s, RegionConfig{})
	instances, err := b.DescribeInstances(t.Context(), inventoryScope(), resource.InstanceQuery{})
	if err != nil || len(instances.Items) != 1 {
		t.Fatalf("instances=%+v error=%v", instances, err)
	}
}

func TestInventoryZonesAndReadOnlySuite(t *testing.T) {
	s := inventoryScenario()
	s.Nodes = append(s.Nodes, pvefake.Node{Name: "pve2"}, pvefake.Node{Name: "ungrouped"})
	c, f := serve(t, s)
	reg := registration()
	reg.Region.Zones = []backend.Zone{{Letter: "a", Nodes: []string{"pve1"}}, {Letter: "b", Nodes: []string{"pve2"}}}
	b, err := New(t.Context(), c, reg, RegionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, offline := range []bool{false, true} {
		if err := f.SetNodeOnline("pve2", !offline); err != nil {
			t.Fatal(err)
		}
		doc, err := b.RegionCapabilities(t.Context(), reg.Region.Name)
		if err != nil || doc.Validate() != nil || len(doc.Zones) != 2 {
			t.Fatalf("zones=%+v error=%v", doc.Zones, err)
		}
		want := "available"
		if offline {
			want = "impaired"
		}
		if doc.Zones[1].ZoneName != "pve-test-1b" || doc.Zones[1].State != want ||
			!slices.Contains(doc.Zones[0].Nodes, "ungrouped") {
			t.Fatalf("zones=%+v", doc.Zones)
		}
	}
	b.zones = nil
	doc, err := b.RegionCapabilities(t.Context(), reg.Region.Name)
	if err != nil || len(doc.Zones) != 1 || doc.Zones[0].ZoneName != "pve-test-1a" || len(doc.Zones[0].Nodes) != 3 {
		t.Fatalf("default zone=%+v error=%v", doc.Zones, err)
	}
}

func TestInventoryPagingAndFailures(t *testing.T) {
	s := inventoryScenario()
	for i := 101; i < 202; i++ {
		vm := s.VMs[0]
		vm.VMID = i
		s.VMs = append(s.VMs, vm)
	}
	b, f := networkBackend(t, s, RegionConfig{})
	before := len(f.Requests())
	first, err := b.DescribeInstances(t.Context(), inventoryScope(),
		resource.InstanceQuery{Page: resource.PageRequest{Size: 100}})
	if err != nil || len(first.Items) != 100 || first.NextToken == "" || len(f.Requests())-before != 101 {
		t.Fatalf("page=%+v calls=%d error=%v", first, len(f.Requests())-before, err)
	}
	last, err := b.DescribeInstances(t.Context(), inventoryScope(),
		resource.InstanceQuery{Page: resource.PageRequest{Token: first.NextToken}})
	if err != nil || len(last.Items) != 2 || last.NextToken != "" {
		t.Fatalf("last=%+v error=%v", last, err)
	}
	_, err = b.DescribeInstances(t.Context(), inventoryScope(),
		resource.InstanceQuery{Page: resource.PageRequest{Token: "../bad"}})
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("invalid cursor: %v", err)
	}
	for _, status := range []int{403, 503} {
		for _, path := range []string{"/cluster/resources", "/nodes", "/nodes/pve1/qemu/100/config"} {
			t.Run(fmt.Sprint(status)+path, func(t *testing.T) {
				s := inventoryScenario()
				s.Tokens[0].Secret = "test-secret"
				_, f := serve(t, s)
				c := startupClient(t, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/api2/json"+path {
						w.WriteHeader(status)
						return
					}
					f.ServeHTTP(w, r)
				})
				b, err := New(t.Context(), c, registration(), RegionConfig{})
				if err != nil {
					t.Fatal(err)
				}
				var he *pveclient.HTTPError
				_, err = b.DescribeInstances(t.Context(), inventoryScope(),
					resource.InstanceQuery{IDs: []resource.InstanceID{powerID(t)}})
				if path == "/nodes" {
					_, err = b.availabilityZones(t.Context())
				}
				if strings.HasSuffix(path, "/config") && resource.CodeOf(err) != resource.CodeUnavailable {
					t.Fatalf("unreadable config was not unavailable: %v", err)
				}
				if !errors.As(err, &he) || he.Status != status || !strings.Contains(err.Error(), path) {
					t.Fatalf("error=%v", err)
				}
			})
		}
	}
}

func TestInventoryFiltersBeforePaging(t *testing.T) {
	s := inventoryScenario()
	s.VMs = nil
	ids, _ := NewIDs("test")
	var matches []resource.InstanceID
	for i := 100; i < 202; i++ {
		uuid := fmt.Sprintf("5f0c3e9a-8b5d-4b8e-9a51-%012d", i)
		cfg := map[string]string{"smbios1": "uuid=" + uuid}
		if i >= 200 {
			cfg["lock"] = "clone"
			id, _, err := ids.Instance(VM{UUID: uuid})
			if err != nil {
				t.Fatal(err)
			}
			matches = append(matches, id)
		}
		s.VMs = append(s.VMs, pvefake.VM{
			VMID: i, Node: "pve1", Pool: "123456789012", Status: "running", Config: cfg,
		})
	}
	s.VMs = append(s.VMs, pvefake.VM{
		VMID: 999, Node: "pve1", Pool: "999999999999", Status: "running",
		Config: map[string]string{"smbios1": "uuid=5f0c3e9a-8b5d-4b8e-9a51-000000000999", "lock": "clone"},
	})
	for _, tc := range []struct {
		name  string
		query resource.InstanceQuery
	}{
		{"id", resource.InstanceQuery{IDs: matches}},
		{"state", resource.InstanceQuery{States: []resource.InstanceState{resource.InstancePending}}},
		{"id-and-state", resource.InstanceQuery{IDs: matches, States: []resource.InstanceState{resource.InstancePending}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, f := networkBackend(t, s, RegionConfig{})
			before := len(f.Requests())
			q := tc.query
			q.Page.Size = 1
			first, err := b.DescribeInstances(t.Context(), inventoryScope(), q)
			if err != nil || len(first.Items) != 1 || first.NextToken == "" ||
				!slices.Contains(matches, first.Items[0].ID) {
				t.Fatalf("later-page match missing: page=%+v error=%v", first, err)
			}
			q.Page.Token = first.NextToken
			last, err := b.DescribeInstances(t.Context(), inventoryScope(), q)
			if err != nil || len(last.Items) != 1 || last.NextToken != "" ||
				!slices.Contains(matches, last.Items[0].ID) || last.Items[0].ID == first.Items[0].ID {
				t.Fatalf("filtered continuation=%+v error=%v", last, err)
			}
			for _, request := range f.Requests()[before:] {
				if strings.Contains(request, "/qemu/999/") {
					t.Fatalf("foreign config read: %s", request)
				}
			}
		})
	}
}

func TestInventoryConfigDefaults(t *testing.T) {
	s := inventoryScenario()
	s.VMs[0].Config = map[string]string{"memory": "1024"}
	b, _ := networkBackend(t, s, RegionConfig{})
	page, err := b.DescribeInstances(t.Context(), inventoryScope(), resource.InstanceQuery{})
	if err != nil || len(page.Items) != 1 || page.Items[0].InstanceType != "vws.small" {
		t.Fatalf("PVE default cores/sockets: page=%+v error=%v", page, err)
	}
}

func TestInventoryRegionsUseRegistry(t *testing.T) {
	g := store.New(store.NewMemory())
	b, f := networkBackend(t, inventoryScenario(), RegionConfig{})
	svc := cloud.New(cloud.Config{Backends: b.Set(), Capabilities: b, Regions: g.Catalog()})
	before := len(f.Requests())
	caller := resource.Caller{Account: inventoryScope().Account}
	for _, name := range []string{"pve-first-1", "pve-second-1"} {
		if _, err := g.Regions().Create(t.Context(), store.Region{Name: name}); err != nil {
			t.Fatal(err)
		}
		names, err := svc.RegionNames(t.Context(), caller)
		if err != nil || !slices.Contains(names, name) {
			t.Fatalf("new registration invisible: %v %v", names, err)
		}
	}
	_, err := g.AWSAccounts().Create(t.Context(), store.AWSAccount{
		ID: "123456789012", AllowedRegions: []string{"pve-first-1", "us-west-2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	names, err := svc.RegionNames(t.Context(), caller)
	if err != nil || !slices.Equal(names, []string{"pve-first-1", "pve-second-1", "us-west-2"}) ||
		len(f.Requests()) != before {
		t.Fatalf("registry-only regions=%v PVE requests=%d error=%v", names, len(f.Requests())-before, err)
	}
}
