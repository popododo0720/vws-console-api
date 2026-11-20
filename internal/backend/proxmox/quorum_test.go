package proxmox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

type gateClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *gateClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *gateClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// gateFor returns a gate over b whose clock the test moves.
func gateFor(b *Backend) (*QuorumGate, *gateClock) {
	clock := &gateClock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	gate := NewQuorumGate(b)
	gate.now = clock.now
	return gate, clock
}

func testGate(t *testing.T, s pvefake.Scenario) (*QuorumGate, *pvefake.Fake, *gateClock) {
	t.Helper()
	client, fake := serve(t, s)
	b, err := New(t.Context(), client, registration(), RegionConfig{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	gate, clock := gateFor(b)
	return gate, fake, clock
}

func wantUnavailable(t *testing.T, err error, what string) {
	t.Helper()
	if resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("%s: %v, want Unavailable", what, err)
	}
}

func TestQuorumGateStartsClosed(t *testing.T) {
	gate, _, _ := testGate(t, scenario())
	wantUnavailable(t, gate.Admit(t.Context()), "before the first check")
}

func TestQuorumGateFreshness(t *testing.T) {
	for _, age := range []time.Duration{0, quorumFresh, quorumFresh + time.Nanosecond} {
		t.Run(age.String(), func(t *testing.T) {
			gate, fake, clock := testGate(t, scenario())
			gate.check(t.Context())
			clock.advance(age)
			before := len(fake.Requests())
			err := gate.Admit(t.Context())
			if (err == nil) != (age <= quorumFresh) {
				t.Fatalf("a check %s old: admission %v", age, err)
			}
			if err != nil {
				wantUnavailable(t, err, "stale check")
			}
			if len(fake.Requests()) != before {
				t.Fatal("admission issued a PVE request")
			}
		})
	}
}

func TestQuorumGateClosesWhenQuorumIsLost(t *testing.T) {
	gate, fake, clock := testGate(t, scenario())
	gate.check(t.Context())
	if err := gate.Admit(t.Context()); err != nil {
		t.Fatal(err)
	}
	fake.SetQuorate(false)
	clock.advance(2 * time.Second)
	gate.check(t.Context())
	wantUnavailable(t, gate.Admit(t.Context()), "lost quorum")
	fake.SetQuorate(true)
	gate.check(t.Context())
	if err := gate.Admit(t.Context()); err != nil {
		t.Fatalf("recovered quorum: %v", err)
	}
}

func TestQuorumGateClosesWhenPVEFails(t *testing.T) {
	fake, err := pvefake.New(scenario())
	if err != nil {
		t.Fatal(err)
	}
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() && strings.HasSuffix(r.URL.Path, "/cluster/status") {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		fake.ServeHTTP(w, r)
	}))
	defer srv.Close()
	client, err := pveclient.New(pveclient.Config{
		BaseURL: srv.URL, TokenID: "vws@pve!inventory", Secret: "fake-secret", HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(t.Context(), client, registration(), RegionConfig{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	gate, clock := gateFor(b)
	gate.check(t.Context())
	if err := gate.Admit(t.Context()); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	clock.advance(time.Second)
	gate.check(t.Context())
	wantUnavailable(t, gate.Admit(t.Context()), "failed check")
}

// A standalone node has no cluster row; its own online state is the quorum.
func TestQuorumGateStandaloneUsesLocalNode(t *testing.T) {
	s := scenario()
	s.Cluster = ""
	gate, fake, _ := testGate(t, s)
	gate.check(t.Context())
	if err := gate.Admit(t.Context()); err != nil {
		t.Fatalf("online standalone node: %v", err)
	}
	if err := fake.SetNodeOnline("pve1", false); err != nil {
		t.Fatal(err)
	}
	gate.check(t.Context())
	wantUnavailable(t, gate.Admit(t.Context()), "offline standalone node")
}

func TestQuorumGateReportsAPINode(t *testing.T) {
	gate, _, _ := testGate(t, scenario())
	if gate.APINode() != "" {
		t.Fatalf("api node before any check: %q", gate.APINode())
	}
	gate.check(t.Context())
	if gate.APINode() != "pve1" {
		t.Fatalf("api node %q, want pve1", gate.APINode())
	}
}

func TestRegionAPIWithoutQuorumRefusesMutationsAndServesReads(t *testing.T) {
	gate, fake, _ := testGate(t, scenario())
	b := gate.backend
	h, err := regionapi.New(regionapi.Config{
		Backend: b.Set(), Capabilities: b, Region: "pve-test-1", Status: b, Gate: gate,
		Version: regionapi.Version{ReleaseLine: "1.0", ClusterName: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	call := func(path, field string) int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/internal/v1/Compute/"+path,
			strings.NewReader(`{"`+field+`":{"account":"123456789012"},"req":{}}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	gate.check(t.Context())
	if got := call("CreateTags", "mutation"); got == http.StatusServiceUnavailable {
		t.Fatalf("mutation with quorum was refused: %d", got)
	}
	fake.SetQuorate(false)
	gate.check(t.Context())
	if got := call("CreateTags", "mutation"); got != http.StatusServiceUnavailable {
		t.Fatalf("mutation without quorum: %d, want 503", got)
	}
	if got := call("DescribeInstances", "scope"); got != http.StatusOK {
		t.Fatalf("read without quorum: %d, want 200", got)
	}
}

func TestQuorumGateStopsFinalizeWrites(t *testing.T) {
	w, m, req := finalizeBackend(t)
	req.Count = 1
	_, err := w.b.RunInstances(t.Context(), m, req)
	checkLaunch(t, err)
	gate, clock := gateFor(w.b)
	gate.check(t.Context())
	// A check older than the window closes the loop before any PVE write.
	clock.advance(quorumFresh + time.Nanosecond)
	before := len(w.f.RequestMethods())
	wantUnavailable(t, w.b.FinalizeLaunches(t.Context(), gate.Admit), "stale quorum check")
	assertSweepReadOnly(t, w, before)
	gate.check(t.Context())
	checkLaunch(t, w.b.FinalizeLaunches(t.Context(), gate.Admit))
}

func TestQuorumGateRefusesAfterRunStops(t *testing.T) {
	gate, _, _ := testGate(t, scenario())
	gate.now = time.Now
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		gate.Run(ctx)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for gate.Admit(t.Context()) != nil {
		if time.Now().After(deadline) {
			t.Fatal("gate never opened")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	wantUnavailable(t, gate.Admit(t.Context()), "after the poller stopped")
	gate.check(t.Context())
	wantUnavailable(t, gate.Admit(t.Context()), "after a late check")
}
