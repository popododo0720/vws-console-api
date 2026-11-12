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
	f, err := pvefake.New(pvefake.Scenario{
		Cluster: "test", Version: pvefake.Version{Version: "9.2", Release: "9.2"},
		Nodes: []pvefake.Node{{Name: "pve1"}},
		Roles: []pvefake.Role{{ID: "PVEAuditor", Privs: []string{"Sys.Audit", "VM.Audit", "Datastore.Audit"}}},
		Tokens: []pvefake.Token{{
			ID: "vws@pve!inventory", Secret: "fake-secret",
			ACL: []pvefake.ACE{{Path: "/", Role: "PVEAuditor"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		for _, request := range f.Requests() {
			if !strings.HasPrefix(request, "GET ") {
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
	}, proxmox.RegionConfig{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
