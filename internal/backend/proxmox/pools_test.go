package proxmox

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/secret"
	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/audit"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

func TestProjectMappingRefusesUnknownPool(t *testing.T) {
	s := scenario()
	s.Roles[0].Privs = append(s.Roles[0].Privs, "Pool.Audit")
	s.Pools = []string{"existing"}
	c, _ := serve(t, s)
	b, err := New(t.Context(), c, registration(), RegionConfig{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	h, err := regionapi.New(regionapi.Config{
		Backend: b.Set(), Capabilities: b, Region: "pve-test-1", Pools: b,
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
	g := store.New(store.NewMemory())
	if _, err := g.Regions().Create(t.Context(), store.Region{Name: "pve-test-1", RegionEndpoint: srv.URL}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.AWSAccounts().Create(t.Context(), store.AWSAccount{ID: "123456789012"}); err != nil {
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
	var auditLog bytes.Buffer
	admin := console.New(console.Config{
		Registry: g, AdminKey: key, Audit: audit.New(&auditLog),
		Auth: console.BearerTokens{"root": {
			Account: account, Root: true, Principal: "arn:aws:iam::123456789012:root",
		}},
		RegionPool: func(ctx context.Context, endpoint, pool string) (bool, error) {
			client, err := regionapi.NewClient(endpoint, config)
			if err != nil {
				return false, err
			}
			defer client.Close()
			return client.PoolExists(ctx, pool)
		},
	})
	for _, tc := range []struct {
		pool, aws, match, message string
		want                      int
	}{
		{"missing-pool", "123456789012", `"0"`, "missing-pool", 400},
		{"existing", "999999999999", `"0"`, "999999999999", 400},
		{"existing", "123456789012", `"0"`, "existing", 200},
		{"existing", "123456789012", `"0"`, "changed", 409},
	} {
		body := `{"pools":[{"region":"pve-test-1","pool":"` + tc.pool + `"}],"awsAccounts":["` + tc.aws + `"]}`
		req := httptest.NewRequestWithContext(t.Context(), "PUT", "/api/v1/admin/projects/123456789012",
			strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer root")
		req.Header.Set("If-Match", tc.match)
		rec := httptest.NewRecorder()
		admin.ServeHTTP(rec, req)
		if rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.message) {
			t.Fatalf("mapping through pvefake: %d %s", rec.Code, rec.Body)
		}
		t.Logf("PUT project pool=%s account=%s If-Match=%s -> %d %s",
			tc.pool, tc.aws, tc.match, rec.Code, rec.Body)
	}
	if strings.Count(auditLog.String(), "\n") != 4 {
		t.Fatalf("audited %d requests, want 4", strings.Count(auditLog.String(), "\n"))
	}
}

func TestRegionPoolCheckSurvivesRestartAndRetry(t *testing.T) {
	s := scenario()
	s.Roles[0].Privs = append(s.Roles[0].Privs, "Pool.Audit")
	s.Pools = []string{"empty", strings.Repeat("a", 64), "123456789012", "A-z_0.1"}
	c, pve := serve(t, s)
	config := daemonCertificates(t, t.TempDir())
	for range 2 {
		b, err := New(t.Context(), c, registration(), RegionConfig{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		h, err := regionapi.New(regionapi.Config{
			Backend: b.Set(), Capabilities: b, Region: "pve-test-1", Pools: b,
			Version: regionapi.Version{ReleaseLine: "1.0", ClusterName: "test"},
		})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewUnstartedServer(h)
		srv.TLS = config.Clone()
		srv.TLS.ClientAuth, srv.TLS.ClientCAs = tls.RequireAndVerifyClientCert, config.RootCAs
		srv.StartTLS()
		t.Cleanup(srv.Close)
		client, err := regionapi.NewClient(srv.URL, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.Close)
		for range 2 {
			for _, pool := range append(s.Pools, "missing") {
				exists, err := client.PoolExists(t.Context(), pool)
				if err != nil || exists != (pool != "missing") {
					t.Fatalf("pool %q: exists=%t err=%v", pool, exists, err)
				}
				t.Logf("GET /internal/v1/pools/%s -> exists=%t", pool, exists)
			}
		}
		client.Close()
		srv.Close()
	}
	for _, request := range pve.Requests() {
		if !strings.HasPrefix(request, "GET ") {
			t.Fatalf("pool check mutated PVE: %s", request)
		}
	}
}

func TestRegionPoolFailureIsUnavailableWithoutCredentials(t *testing.T) {
	c, _ := serve(t, scenario())
	b := &Backend{client: c}
	h, err := regionapi.New(regionapi.Config{
		Backend: b.Set(), Capabilities: b, Region: "pve-test-1", Pools: b,
		Version: regionapi.Version{ReleaseLine: "1.0", ClusterName: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/internal/v1/pools/private", nil))
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "region pool check failed") {
		t.Fatalf("PVE denied: %d %s", rec.Code, rec.Body)
	}
	for _, secret := range []string{"fake-secret", "vws@pve", "/pool/private", "http://", "https://"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("private diagnostic escaped: %s", rec.Body)
		}
	}
	t.Logf("GET /internal/v1/pools/private -> %d %s", rec.Code, rec.Body)
}
