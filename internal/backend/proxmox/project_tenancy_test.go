package proxmox

import (
	"bytes"
	"context"
	"crypto/tls"
	"maps"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/secret"
	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/audit"
	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/backend/regionset"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

func TestProjectRemappingChangesInventoryWithoutRestart(t *testing.T) {
	s := inventoryScenario()
	for i, pool := range []string{"team-a", "team-b", ""} {
		vm := s.VMs[0]
		vm.VMID, vm.Pool, vm.Config = 101+i, pool, maps.Clone(vm.Config)
		vm.Config["smbios1"] = "uuid=5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a1" + string(rune('1'+i))
		s.VMs = append(s.VMs, vm)
	}
	b, pve := networkBackend(t, s, RegionConfig{
		ReadOnly: true, DefaultProject: "999999999999",
		Pools: map[string]string{"a": "team-a", "b": "team-b", "legacy": "123456789012", "default": "999999999999"},
	})
	h, err := regionapi.New(regionapi.Config{
		Backend: b.Set(), Capabilities: b, Region: "pve-test-1", Pools: b, CheckScope: ScopeCheck(b),
		Version: regionapi.Version{ReleaseLine: "1.0", ClusterName: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	config := daemonCertificates(t, t.TempDir())
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = config.Clone()
	srv.TLS.ClientAuth, srv.TLS.ClientCAs = tls.RequireAndVerifyClientCert, config.RootCAs
	srv.StartTLS()
	defer srv.Close()
	client, err := regionapi.NewClient(srv.URL, config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	g := store.New(store.NewMemory())
	if _, err := g.Regions().Create(t.Context(), store.Region{Name: "pve-test-1", RegionEndpoint: srv.URL}); err != nil {
		t.Fatal(err)
	}
	routed, err := regionset.New(g.Catalog(), func(
		context.Context, backend.ProxmoxRegion,
	) (regionclient.Transport, error) {
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := inventoryScope()
	scope.Region, scope.Pool = "pve-test-1", "forged-client-pool"
	checkView := func(vmid int) {
		t.Helper()
		page, err := routed.Compute.DescribeInstances(t.Context(), scope, resource.InstanceQuery{})
		ids, idsErr := NewIDs("test")
		want, _, idErr := ids.Instance(VM{UUID: option(s.VMs[vmid-100].Config["smbios1"], "uuid")})
		if err != nil || idsErr != nil || idErr != nil || len(page.Items) != 1 || page.Items[0].ID != want {
			t.Fatalf("project view for VM %d: %+v, %v (ids: %v, %v)", vmid, page, err, idsErr, idErr)
		}
	}
	checkView(100)
	key, err := secret.New("global", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var auditLog bytes.Buffer
	admin := console.New(console.Config{
		Registry: g, AdminKey: key, Audit: audit.New(&auditLog),
		Auth:       console.BearerTokens{"root": {Account: scope.Account, Root: true}},
		RegionPool: func(ctx context.Context, _, pool string) (bool, error) { return client.PoolExists(ctx, pool) },
	})
	version := `"0"`
	for i, pool := range []string{"team-a", "team-b", "team-b"} {
		req := httptest.NewRequestWithContext(t.Context(), "PUT", "/api/v1/admin/projects/123456789012",
			strings.NewReader(`{"pools":[{"region":"pve-test-1","pool":"`+pool+`"}],"awsAccounts":[]}`))
		req.Header.Set("Authorization", "Bearer root")
		req.Header.Set("If-Match", version)
		rec := httptest.NewRecorder()
		admin.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("remap %s: %d %s", pool, rec.Code, rec.Body)
		}
		version = rec.Header().Get("ETag")
		if version == "" {
			t.Fatal("project mapping response omitted ETag")
		}
		vmid := 102
		if i == 0 {
			vmid = 101
		}
		checkView(vmid)
	}
	if err := pve.MoveVM(102, "team-a"); err != nil {
		t.Fatal(err)
	}
	page, err := routed.Compute.DescribeInstances(t.Context(), scope, resource.InstanceQuery{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("moved VM remained visible: %+v %v", page, err)
	}
	defaultAccount, err := resource.Parse[resource.AccountID]("999999999999")
	if err != nil {
		t.Fatal(err)
	}
	page, err = routed.Compute.DescribeInstances(t.Context(), backend.Scope{
		Account: defaultAccount, Region: scope.Region,
	}, resource.InstanceQuery{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("unpooled VM left default project: %+v %v", page, err)
	}
}

func TestBoundScopePoolAndManagedPoolAdmissionAfterRestart(t *testing.T) {
	s := inventoryScenario()
	s.VMs[0].Pool = "team-a"
	client, pve := serve(t, s)
	cfg := RegionConfig{ReadOnly: true, Pools: map[string]string{"operator-slot": "team-a"}}
	for range 2 {
		b, err := New(t.Context(), client, registration(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		scope := inventoryScope()
		scope.Pool = "team-a"
		checkScope := ScopeCheck(b)
		for range 2 {
			before := len(pve.Requests())
			for _, pool := range []string{"", "foreign", "operator-slot", "team-a/child", "team-a\x00"} {
				scope.Pool = pool
				if err := checkScope(scope); resource.CodeOf(err) != resource.CodePermissionDenied {
					t.Fatalf("unmanaged scope pool %q accepted: %v", pool, err)
				}
			}
			if len(pve.Requests()) != before {
				t.Fatal("unmanaged scope reached PVE")
			}
			scope.Pool = "team-a"
			if err := checkScope(scope); err != nil {
				t.Fatal(err)
			}
			page, err := b.DescribeInstances(t.Context(), scope, resource.InstanceQuery{})
			if err != nil || len(page.Items) != 1 || page.Items[0].OwnerID != scope.Account {
				t.Fatalf("bound inventory after restart/retry: %+v %v", page, err)
			}
			pool, err := b.poolForMutation(t.Context(), scope)
			if err != nil || pool != scope.Pool {
				t.Fatalf("mutation ignored bound pool: %q %v", pool, err)
			}
		}
	}
}
