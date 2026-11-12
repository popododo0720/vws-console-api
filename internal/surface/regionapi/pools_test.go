package regionapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
)

type poolProbe struct {
	calls atomic.Int32
}

func (p *poolProbe) PoolExists(ctx context.Context, _ string) (bool, error) {
	p.calls.Add(1)
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 5*time.Second {
		return false, context.DeadlineExceeded
	}
	return true, nil
}

func TestRegionPoolInputBounds(t *testing.T) {
	probe := &poolProbe{}
	cfg := config(fake.New(fake.Options{}).Set())
	cfg.Pools = probe
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"a%2Fb", "%2e%2e", "a%00b", "a%3Fb", "a%23b", "a%25b", "-a", strings.Repeat("a", 65), "valid?unexpected=1",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/internal/v1/pools/"+path, nil))
		if rec.Code != 400 {
			t.Fatalf("path %q: %d %s", path, rec.Code, rec.Body)
		}
	}
	if probe.calls.Load() != 0 {
		t.Fatalf("invalid paths reached pool probe %d times", probe.calls.Load())
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/internal/v1/pools/valid", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"exists":true`) || probe.calls.Load() != 1 {
		t.Fatalf("bounded probe: %d %s calls=%d", rec.Code, rec.Body, probe.calls.Load())
	}
	cfg.Pools = nil
	h, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/internal/v1/pools/valid", nil))
	if rec.Code != 503 {
		t.Fatalf("missing pool provider: %d %s", rec.Code, rec.Body)
	}
}

func TestPoolClientRejectsInvalidIDsBeforeTransport(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer srv.Close()
	client := &Client{base: srv.URL, http: srv.Client()}
	for _, pool := range []string{"", ".", "..", "a/b", "a?b", "a#b", "a\x00b", "a%2fb", strings.Repeat("a", 65)} {
		if exists, err := client.PoolExists(t.Context(), pool); err == nil || exists {
			t.Fatalf("pool %q: %t %v", pool, exists, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid pool reached HTTP")
	}
}

func TestPoolClientCancellationAndTransportRecovery(t *testing.T) {
	client, srv := loopback(t, config(fake.New(fake.Options{}).Set()))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if exists, err := client.PoolExists(ctx, "valid"); exists || err == nil {
		t.Fatalf("canceled read: %t %v", exists, err)
	}
	srv.Close()
	if exists, err := client.PoolExists(t.Context(), "valid"); exists || err == nil {
		t.Fatalf("closed region: %t %v", exists, err)
	}
	probe := &poolProbe{}
	cfg := config(fake.New(fake.Options{}).Set())
	cfg.Pools = probe
	restarted, _ := loopback(t, cfg)
	for range 2 {
		if exists, err := restarted.PoolExists(t.Context(), "valid"); !exists || err != nil {
			t.Fatalf("restarted region: %t %v", exists, err)
		}
	}
}
