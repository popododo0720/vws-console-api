package proxmox

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

type healthStore struct {
	store.Backend
	writes int
}

func (s *healthStore) Create(ctx context.Context, key string, value []byte) (store.Version, error) {
	s.writes++
	return s.Backend.Create(ctx, key, value)
}

func (s *healthStore) Update(
	ctx context.Context, key string, value []byte, version store.Version,
) (store.Version, error) {
	s.writes++
	return s.Backend.Update(ctx, key, value, version)
}

func (s *healthStore) Delete(ctx context.Context, key string, version store.Version) error {
	s.writes++
	return s.Backend.Delete(ctx, key, version)
}

func healthConsole(t *testing.T, endpoint string, config *tls.Config) (http.Handler, *healthStore) {
	t.Helper()
	counting := &healthStore{Backend: store.NewMemory()}
	registry := store.New(counting)
	if _, err := registry.Regions().Create(t.Context(), store.Region{
		Name: "pve-test-1", RegionEndpoint: endpoint,
	}); err != nil {
		t.Fatal(err)
	}
	counting.writes = 0
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return console.New(console.Config{
		Registry: registry,
		Auth: console.BearerTokens{
			"root": {Account: account, Root: true}, "user": {Account: account},
		},
		RegionStatus: func(ctx context.Context, endpoint string) (resource.RegionStatus, error) {
			client, err := regionapi.NewClient(endpoint, config)
			if err != nil {
				return resource.RegionStatus{}, err
			}
			defer client.Close()
			return client.Status(ctx)
		},
	}), counting
}

func healthRequest(ctx context.Context, h http.Handler, name, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/admin/regions/"+name+"/health", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAdminHealthReadsRegionWithoutWrites(t *testing.T) {
	c, fake := serve(t, scenario())
	b, err := New(t.Context(), c, registration(), RegionConfig{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	h, err := regionapi.New(regionapi.Config{
		Backend: b.Set(), Capabilities: b, Region: "pve-test-1", Status: b,
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
	admin, counting := healthConsole(t, srv.URL, config)
	for _, quorum := range []bool{true, false, false} {
		fake.SetQuorate(quorum)
		rec := healthRequest(t.Context(), admin, "pve-test-1", "root")
		var result struct {
			resource.RegionStatus
			Status    string    `json:"status"`
			CheckedAt time.Time `json:"checkedAt"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if rec.Code != 200 || result.Status != "ok" || result.Quorate != quorum ||
			len(result.Nodes) != 1 || result.Nodes[0].Name != "pve1" || !result.Nodes[0].Online ||
			result.Leader != nil || result.LastError != nil || result.CheckedAt.IsZero() {
			t.Fatalf("health: %d %s", rec.Code, rec.Body)
		}
		if !strings.Contains(rec.Body.String(), `"leader":null`) ||
			!strings.Contains(rec.Body.String(), `"lastError":null`) || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("health wire: %s", rec.Body)
		}
	}
	for _, tc := range []struct {
		name, token string
		status      int
	}{
		{"pve-test-1", "user", 403}, {"bad", "root", 400}, {"pve-missing-1", "root", 404},
	} {
		if rec := healthRequest(t.Context(), admin, tc.name, tc.token); rec.Code != tc.status {
			t.Fatalf("%s/%s: %d %s", tc.name, tc.token, rec.Code, rec.Body)
		}
	}
	if counting.writes != 0 {
		t.Fatalf("health wrote %d records", counting.writes)
	}
}

func TestAdminHealthStalledRegionIsBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	admin, counting := healthConsole(t, "https://"+ln.Addr().String(), daemonCertificates(t, t.TempDir()))
	done := make(chan *httptest.ResponseRecorder, 1)
	start := time.Now()
	go func() { done <- healthRequest(t.Context(), admin, "pve-test-1", "root") }()
	select {
	case rec := <-done:
		var result struct {
			Status    string                      `json:"status"`
			LastError *resource.RegionStatusError `json:"lastError"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if rec.Code != 200 || result.Status != "unreachable" || result.LastError == nil ||
			!strings.Contains(result.LastError.Message, "context deadline exceeded") ||
			result.LastError.Time.IsZero() || time.Since(start) > 5*time.Second+200*time.Millisecond {
			t.Fatalf("stalled health: %s after %s", rec.Body, time.Since(start))
		}
	case <-ctx.Done():
		t.Fatal("health did not return within its deadline")
	}
	if counting.writes != 0 {
		t.Fatalf("unreachable health wrote %d records", counting.writes)
	}
}

func TestStandaloneStatusFollowsLocalOnline(t *testing.T) {
	s := scenario()
	s.Cluster = ""
	c, fake := serve(t, s)
	b, err := New(t.Context(), c, registration(), RegionConfig{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, online := range []bool{true, false, true} {
		if err := fake.SetNodeOnline("pve1", online); err != nil {
			t.Fatal(err)
		}
		got, err := b.Status(t.Context())
		if err != nil || got.Quorate != online || len(got.Nodes) != 1 || got.Nodes[0].Online != online {
			t.Fatalf("online %t: %+v %v", online, got, err)
		}
	}
}

func TestStatusRemembersFailureAndRedactsCredentials(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message":"PVEAPIToken=vws@pve!inventory=fake-secret fake-secret"}`))
			return
		}
		w.Write([]byte(`{"data":[{"type":"node","name":"local","local":1,"online":1}]}`))
	}))
	defer srv.Close()
	c, err := pveclient.New(pveclient.Config{
		BaseURL: srv.URL, TokenID: "vws@pve!inventory", Secret: "fake-secret", HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	b := &Backend{client: c}
	fail.Store(true)
	first, err := b.Status(t.Context())
	if err != nil || first.LastError == nil || first.LastError.Time.IsZero() ||
		strings.Contains(first.LastError.Message, "fake-secret") ||
		strings.Contains(first.LastError.Message, "vws@pve!inventory") {
		t.Fatalf("failed status: %+v %v", first, err)
	}
	fail.Store(false)
	next, err := b.Status(t.Context())
	if err != nil || !next.Quorate || next.LastError == nil || *next.LastError != *first.LastError {
		t.Fatalf("recovered status: %+v %v", next, err)
	}
	fail.Store(true)
	last, err := b.Status(t.Context())
	if err != nil || !last.LastError.Time.After(first.LastError.Time) {
		t.Fatalf("latest failure not retained: %+v %v", last, err)
	}
	restarted := &Backend{client: c}
	fail.Store(false)
	fresh, err := restarted.Status(t.Context())
	if err != nil || fresh.LastError != nil {
		t.Fatalf("restart retained an in-memory error: %+v %v", fresh, err)
	}
}
