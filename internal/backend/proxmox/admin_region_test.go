package proxmox

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/secret"
	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
)

func TestAdminRegionDeleteNeverCallsPVE(t *testing.T) {
	pve, err := pvefake.New(scenario())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(pve)
	defer srv.Close()
	g := store.New(store.NewMemory())
	if _, err := g.Regions().Create(t.Context(), store.Region{
		Name: "pve-test-1", ClusterName: "test", PVEAPIURL: srv.URL, RegionEndpoint: srv.URL,
	}); err != nil {
		t.Fatal(err)
	}
	key, err := secret.New("global", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	h := console.New(console.Config{
		Registry: g,
		AdminKey: key,
		IAM:      iam.NewFake(),
		Auth:     console.BearerTokens{"tok": {Account: account, Root: true}},
	})
	req := httptest.NewRequestWithContext(t.Context(), "DELETE", "/api/v1/admin/regions/pve-test-1", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 204 || len(pve.Requests()) != 0 {
		t.Fatalf("delete status=%d PVE calls=%v", rec.Code, pve.Requests())
	}
}
