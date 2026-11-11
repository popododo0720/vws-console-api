package proxmox

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

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
