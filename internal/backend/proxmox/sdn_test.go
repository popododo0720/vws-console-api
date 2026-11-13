package proxmox

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func sdnScenario() pvefake.Scenario {
	s := scenario()
	s.Tokens[0].Secret = "test-secret"
	s.Pools, s.SDNZones = []string{"tenant_pool", "other"}, []string{"tenant", "outside"}
	s.Roles = append(s.Roles, pvefake.Role{ID: "SDN", Privs: []string{"SDN.Allocate", "SDN.Audit"}},
		pvefake.Role{ID: "Pools", Privs: []string{"Pool.Audit", "VM.Audit"}})
	no := false
	s.Tokens[0].ACL = append(s.Tokens[0].ACL,
		pvefake.ACE{Path: "/sdn", Role: "SDN", Propagate: &no},
		pvefake.ACE{Path: "/sdn/zones/tenant", Role: "SDN"},
		pvefake.ACE{Path: "/pool", Role: "Pools"})
	return s
}

func sdnBackend(t *testing.T, s pvefake.Scenario) (*Backend, *pvefake.Fake) {
	t.Helper()
	f, err := pvefake.New(s)
	checkLaunch(t, err)
	cfg, err := ParseRegion([]byte("sdn_zone: tenant\npools: {'123456789012': tenant_pool}\n"))
	checkLaunch(t, err)
	b, err := New(t.Context(), startupClient(t, f.ServeHTTP), registration(), cfg)
	checkLaunch(t, err)
	return b, f
}

func TestStartupSDNScope(t *testing.T) {
	for _, tc := range []struct {
		name, zone, path, check string
		propagate               bool
		readOnly                bool
	}{
		{name: "scoped", zone: "tenant"},
		{name: "missing zone", zone: "missing", check: "sdn_zone"},
		{name: "no zone", check: "privileges"},
		{name: "foreign", zone: "tenant", path: "/sdn/zones/outside", check: "privileges"},
		{name: "propagated root", zone: "tenant", propagate: true, check: "privileges"},
		{name: "read only", zone: "tenant", readOnly: true, check: "privileges"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := sdnScenario()
			if tc.path != "" {
				s.Tokens[0].ACL = append(s.Tokens[0].ACL, pvefake.ACE{Path: tc.path, Role: "SDN"})
			}
			s.Tokens[0].ACL[1].Propagate = &tc.propagate
			f, err := pvefake.New(s)
			checkLaunch(t, err)
			b, err := New(t.Context(), startupClient(t, f.ServeHTTP), registration(),
				RegionConfig{SDNZone: tc.zone, ReadOnly: tc.readOnly})
			var sc *selfCheckError
			if tc.check == "" {
				probed := slices.Contains(f.Requests(), "GET /api2/json/access/permissions?path=%2Fsdn%2Fzones%2Fvwsprobe")
				if err != nil || b == nil || !probed {
					t.Fatalf("scoped grant: %v; requests=%v", err, f.Requests())
				}
			} else if !errors.As(err, &sc) || sc.check != tc.check || b != nil {
				t.Fatalf("backend=%v error=%v, want check=%s", b, err, tc.check)
			}
		})
	}
}

func TestSDNVPCLifecycle(t *testing.T) {
	b, f := sdnBackend(t, sdnScenario())
	m := volumeMutation()
	req := resource.CreateVpcRequest{Cidr: "10.0.0.0/16"}
	f.FailNext("sdnapply", "apply interrupted")
	if _, err := b.CreateVpc(t.Context(), m, req); err == nil {
		t.Fatal("failed apply succeeded")
	}
	created, err := b.CreateVpc(t.Context(), m, req)
	checkLaunch(t, err)
	rows, err := b.client.SDNVNets(t.Context())
	checkLaunch(t, err)
	ids, _ := NewIDs(b.cluster)
	want, _ := ids.SDNVPC("tenant", rows[0].VNet)
	if len(rows) != 1 || rows[0].State != "" || created.Items[0].ID != want ||
		created.Operation.State != resource.OperationSucceeded {
		t.Fatalf("create=%+v rows=%+v", created, rows)
	}
	restarted, err := New(t.Context(), b.client, Identity(b), b.cfg)
	checkLaunch(t, err)
	replay, err := restarted.CreateVpc(t.Context(), m, req)
	checkLaunch(t, err)
	if replay.Items[0].ID != want || replay.Operation.ID != created.Operation.ID {
		t.Fatal("restart replay changed identity")
	}
	for _, changed := range []backend.Mutation{m, {Scope: m.Scope, Key: m.Key, Fingerprint: strings.Repeat("c", 64)}} {
		_, err := b.CreateVpc(t.Context(), changed, resource.CreateVpcRequest{Cidr: "10.1.0.0/16"})
		if resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
			t.Fatalf("changed CIDR/fingerprint: %v", err)
		}
	}
	other := m
	other.Pool = "other"
	_, err = b.DescribeVpcs(t.Context(), other.Scope, resource.VpcQuery{IDs: []resource.VpcID{want}})
	assertMutationNotFound(t, err, resource.KindVpc, want.String())
	_, err = b.DeleteVpc(t.Context(), other, resource.DeleteVpcRequest{ID: want})
	assertMutationNotFound(t, err, resource.KindVpc, want.String())
	page, err := b.DescribeVpcs(t.Context(), m.Scope, resource.VpcQuery{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Cidr != req.Cidr {
		t.Fatalf("describe=%+v error=%v", page, err)
	}
	f.FailNext("sdnapply", "delete interrupted")
	if _, err := b.DeleteVpc(t.Context(), m, resource.DeleteVpcRequest{ID: want}); err == nil {
		t.Fatal("failed delete apply succeeded")
	}
	_, err = restarted.DeleteVpc(t.Context(), m, resource.DeleteVpcRequest{ID: want})
	checkLaunch(t, err)
	_, err = b.DeleteVpc(t.Context(), m, resource.DeleteVpcRequest{ID: want})
	assertMutationNotFound(t, err, resource.KindVpc, want.String())
}

func TestSDNInventoryAndBoundaries(t *testing.T) {
	s := sdnScenario()
	s.VNets = []pvefake.VNet{
		{Name: "shared", Zone: "tenant", Subnets: []pvefake.Subnet{{ID: "tenant-10.2.0.0-24", CIDR: "10.2.0.0/24"}}},
		{Name: "foreign", Zone: "tenant", Alias: (sdnMarker{"10.0.0.0/16", "other", strings.Repeat("b", 16)}).alias()},
	}
	b, f := sdnBackend(t, s)
	m := volumeMutation()
	ids, _ := NewIDs(b.cluster)
	id, _ := ids.SDNVPC("tenant", "shared")
	_, err := b.DeleteVpc(t.Context(), m, resource.DeleteVpcRequest{ID: id})
	if resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Fatalf("shared delete: %v", err)
	}
	subnets, err := b.DescribeSubnets(t.Context(), m.Scope, resource.SubnetQuery{})
	want, _ := ids.SDNSubnet("shared", "10.2.0.0/24")
	if err != nil || len(subnets.Items) != 1 || subnets.Items[0].ID != want {
		t.Fatalf("subnets=%+v error=%v", subnets, err)
	}
	for _, cidr := range []string{"bad", "::/16", "10.0.0.1/16", "127.0.0.0/16", "10.0.0.0/29"} {
		if _, err := b.CreateVpc(t.Context(), m, resource.CreateVpcRequest{Cidr: cidr}); err == nil {
			t.Fatalf("accepted %s", cidr)
		}
	}
	_, err = b.CreateVpc(t.Context(), m, resource.CreateVpcRequest{
		Cidr: "10.0.0.0/16", Tags: map[string]string{"Name": "x"},
	})
	if err == nil || !strings.Contains(err.Error(), "TagSpecification") {
		t.Fatalf("tags: %v", err)
	}
	for _, method := range f.RequestMethods() {
		if method != "GET" {
			t.Fatalf("refusals wrote %s", method)
		}
	}
	if err := b.client.CreateVNet(t.Context(), "../foreign", "tenant", ""); err == nil {
		t.Fatal("malformed VNet path accepted")
	}
}

func TestSDNCapabilities(t *testing.T) {
	b, _ := sdnBackend(t, sdnScenario())
	for _, tc := range []struct {
		zone, reason string
		readOnly     bool
	}{
		{zone: "tenant"}, {reason: "NoSDNZone"}, {zone: "tenant", readOnly: true, reason: "ReadOnly"},
	} {
		b.cfg.SDNZone, b.cfg.ReadOnly = tc.zone, tc.readOnly
		doc, err := b.RegionCapabilities(t.Context(), b.region)
		checkLaunch(t, err)
		checkLaunch(t, doc.Validate())
		for _, action := range []string{"ec2:CreateVpc", "ec2:DeleteVpc"} {
			got := doc.Actions[action]
			if got.ReasonCode != tc.reason || (tc.reason == "" && got.State != resource.ActionSupported) {
				t.Fatalf("%s=%+v", action, got)
			}
		}
	}
}
