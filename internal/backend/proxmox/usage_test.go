package proxmox

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/backend/regionset"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

func usageScenario() pvefake.Scenario {
	s := inventoryScenario()
	s.VMs = []pvefake.VM{
		{VMID: 100, Node: "pve1", Pool: "team-a", Status: "running", MaxCPU: 2, MaxMem: 2 << 30, MaxDisk: 20 << 30},
		{VMID: 101, Node: "pve1", Pool: "team-a", Status: "stopped", MaxCPU: 4, MaxMem: 4 << 30, MaxDisk: 40 << 30},
		{VMID: 102, Node: "pve1", Pool: "team-a", Tags: "vws.holder", MaxCPU: 1, MaxMem: 1 << 30, MaxDisk: 8 << 30},
		{VMID: 103, Node: "pve1", Pool: "team-a", Template: true, MaxCPU: 64, MaxMem: 64 << 30, MaxDisk: 64 << 30},
		{VMID: 104, Node: "pve1", Pool: "team-b", MaxCPU: 32, MaxMem: 32 << 30, MaxDisk: 32 << 30},
		{VMID: 105, Node: "pve1", MaxCPU: 8, MaxMem: 8 << 30, MaxDisk: 16 << 30},
	}
	return s
}

func TestUsageAPIAllocationReadOnlyAcrossRestart(t *testing.T) {
	client, pve := serve(t, usageScenario())
	registry := store.NewMemory()
	g := store.New(registry)
	for _, region := range []string{"pve-test-1", "pve-other-1"} {
		if _, err := g.Regions().Create(t.Context(), store.Region{Name: region}); err != nil {
			t.Fatal(err)
		}
	}
	mapping, err := g.Projects().Put(t.Context(), store.Project{
		Project: "123456789012", Pools: []store.ProjectPool{
			{Region: "pve-test-1", Pool: "team-a"}, {Region: "pve-other-1", Pool: "team-b"},
		}, AWSAccounts: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	before, err := registry.List(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	scope := inventoryScope()
	var previous string
	for range 2 {
		b, err := New(t.Context(), client, registration(), RegionConfig{
			ReadOnly: true, Pools: map[string]string{"a": "team-a", "b": "team-b"},
		})
		if err != nil {
			t.Fatal(err)
		}
		regional, err := regionapi.New(regionapi.Config{
			Backend: b.Set(), Capabilities: b, Region: "pve-test-1", CheckScope: ScopeCheck(b),
			Version: regionapi.Version{ReleaseLine: "1.0", ClusterName: "test"},
		})
		if err != nil {
			t.Fatal(err)
		}
		cert := daemonCertificates(t, t.TempDir())
		srv := httptest.NewUnstartedServer(regional)
		srv.TLS = cert.Clone()
		srv.TLS.ClientAuth, srv.TLS.ClientCAs = tls.RequireAndVerifyClientCert, cert.RootCAs
		srv.StartTLS()
		t.Cleanup(srv.Close)
		remote, err := regionapi.NewClient(srv.URL, cert)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(remote.Close)
		set, err := regionset.New(g.Catalog(), func(
			context.Context, backend.ProxmoxRegion,
		) (regionclient.Transport, error) {
			return remote, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		svc := cloud.New(cloud.Config{Backends: set, Regions: g.Catalog()})
		h := console.New(console.Config{
			Service: svc, Registry: g, Region: "pve-test-1", IAM: iam.NewStatic("key", "secret", scope.Account),
			Auth: console.BearerTokens{"root": {
				Account: scope.Account, Principal: iam.RootARN(scope.Account), Root: true,
			}},
		})
		for range 2 {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
				"/api/v1/usage?from=2026-10-01&to=2026-11-01", nil)
			req.Header.Set("Authorization", "Bearer root")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var result struct {
				Items []struct {
					Project string `json:"project"`
					Regions []struct {
						Region     string              `json:"region"`
						Allocation resource.Allocation `json:"allocation"`
					} `json:"regions"`
				} `json:"items"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || rec.Code != http.StatusOK {
				t.Fatalf("usage response: %d %s (%v)", rec.Code, rec.Body, err)
			}
			if len(result.Items) != 1 || result.Items[0].Project != scope.Account.String() ||
				len(result.Items[0].Regions) != 2 {
				t.Fatalf("project regions: %s", rec.Body)
			}
			want := []resource.Allocation{
				{VCPU: 32, MemoryBytes: 32 << 30, DiskBytes: 32 << 30},
				{VCPU: 6, MemoryBytes: 6 << 30, DiskBytes: 68 << 30},
			}
			for i, row := range result.Items[0].Regions {
				if row.Allocation != want[i] || row.Region != mapping.Pools[i].Region {
					t.Fatalf("allocation: %+v; want %+v", row, want[i])
				}
			}
			if previous != "" && previous != rec.Body.String() {
				t.Fatalf("retry or restart changed response: %s -> %s", previous, rec.Body)
			}
			previous = rec.Body.String()
		}
		if len(b.lastInstances) != 0 {
			t.Fatal("usage retained an instance snapshot")
		}
	}
	stored, err := g.Projects().Get(t.Context(), mapping.Project)
	if err != nil || !reflect.DeepEqual(stored, mapping) {
		t.Fatalf("usage wrote registry: %+v %v", stored, err)
	}
	after, err := registry.List(t.Context(), "")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("usage changed registry records: %+v %v", after, err)
	}
	if err := pve.MoveVM(100, "team-b"); err != nil {
		t.Fatal(err)
	}
	b, err := New(t.Context(), client, registration(), RegionConfig{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	scope.Pool = "team-a"
	got, err := b.GetAllocation(t.Context(), scope, struct{}{})
	if err != nil || got.VCPU != 4 || got.DiskBytes != 48<<30 {
		t.Fatalf("live pool move not reflected: %+v %v", got, err)
	}
	if err := pve.SetNodeOnline("pve1", false); err != nil {
		t.Fatal(err)
	}
	if _, err := b.GetAllocation(t.Context(), scope, struct{}{}); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("offline allocation looks like zero: %v", err)
	}
}

func TestAllocationDefaultProjectAndEmptyPool(t *testing.T) {
	c, _ := serve(t, usageScenario())
	b, err := New(t.Context(), c, registration(), RegionConfig{
		ReadOnly: true, DefaultProject: "123456789012",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.GetAllocation(t.Context(), inventoryScope(), struct{}{})
	want := resource.Allocation{VCPU: 8, MemoryBytes: 8 << 30, DiskBytes: 16 << 30}
	if err != nil || got != want {
		t.Fatalf("default project allocation: %+v %v", got, err)
	}
	other, err := resource.Parse[resource.AccountID]("999999999999")
	if err != nil {
		t.Fatal(err)
	}
	got, err = b.GetAllocation(t.Context(), backend.Scope{Account: other}, struct{}{})
	if err != nil || got != (resource.Allocation{}) {
		t.Fatalf("empty project: %+v %v", got, err)
	}
}

func TestAllocationRequiresPoolVisibility(t *testing.T) {
	c, _ := serve(t, scenario())
	b, err := New(t.Context(), c, registration(), RegionConfig{ReadOnly: true, DefaultProject: "123456789012"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.GetAllocation(t.Context(), inventoryScope(), struct{}{})
	if resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Fatalf("hidden pool names exposed as default project: %v", err)
	}
}

func TestAllocationReadFailureAndDeadline(t *testing.T) {
	c, _ := serve(t, usageScenario())
	b, err := New(t.Context(), c, registration(), RegionConfig{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = b.GetAllocation(ctx, inventoryScope(), struct{}{})
	if err == nil || !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "usage pool visibility") {
		t.Fatalf("canceled read: %v", err)
	}
}
