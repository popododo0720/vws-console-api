// Package proxmoxtest supplies a read-only PVE boundary for integration tests.
package proxmoxtest

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
)

// New starts a pvefake-backed region with audit-only credentials.
func New(t testing.TB) *proxmox.Backend {
	t.Helper()
	return newBackend(t, false)
}

// Console starts a pvefake-backed region with pool-scoped console access.
func Console(t testing.TB) *proxmox.Backend {
	t.Helper()
	return newBackend(t, true)
}

func newBackend(t testing.TB, console bool) *proxmox.Backend {
	t.Helper()
	scenario := pvefake.Scenario{
		Cluster: "test", Version: pvefake.Version{Version: "9.2", Release: "9.2"},
		Nodes: []pvefake.Node{{Name: "pve1"}},
		Roles: []pvefake.Role{{ID: "PVEAuditor", Privs: []string{"Sys.Audit", "VM.Audit", "Datastore.Audit", "Pool.Audit"}}},
		VMs: []pvefake.VM{{
			VMID: 100, Node: "pve1", Pool: "123456789012", Status: "running",
			Config: map[string]string{"smbios1": "uuid=5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10"},
		}},
		Tokens: []pvefake.Token{{
			ID: "vws@pve!inventory", Secret: "fake-secret",
			ACL: []pvefake.ACE{{Path: "/", Role: "PVEAuditor"}},
		}},
	}
	if console {
		scenario.Roles = append(scenario.Roles,
			pvefake.Role{ID: "Console", Privs: []string{"VM.Console", "VM.Audit", "Pool.Audit"}})
		scenario.Tokens[0].ACL = append(scenario.Tokens[0].ACL,
			pvefake.ACE{Path: "/pool/123456789012", Role: "Console"})
	}
	f, err := pvefake.New(scenario)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		for _, request := range f.Requests() {
			if !console && !strings.HasPrefix(request, "GET ") {
				t.Errorf("read-only PVE fixture issued %s", request)
			}
		}
	})
	client, err := pveclient.New(pveclient.Config{
		BaseURL: srv.URL, TokenID: "vws@pve!inventory",
		Secret: "fake-secret", HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := proxmox.New(t.Context(), client, proxmox.Registration{
		Region: backend.ProxmoxRegion{Name: "pve-test-1"}, ClusterName: "test",
	}, proxmox.RegionConfig{ReadOnly: !console})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
