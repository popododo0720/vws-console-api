package pveclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// hostServer is a TLS server that counts what reaches its handler.
type hostServer struct {
	*httptest.Server
	hits   atomic.Int64
	bodies chan string
}

func newHostServer(t *testing.T, h http.HandlerFunc) *hostServer {
	t.Helper()
	s := &hostServer{bodies: make(chan string, 16)}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		select {
		case s.bodies <- r.Method + " " + string(body):
		default:
		}
		h(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func ok(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"data":null}`) }

// cut reads the whole request and closes the connection without an answer.
func cut(w http.ResponseWriter, _ *http.Request) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

func deadURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewTLSServer(nil)
	u := srv.URL
	srv.Close()
	return u
}

func failoverClient(t *testing.T, ref *httptest.Server, urls ...string) (*Client, *Endpoints) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ref.Certificate())
	base := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	t.Cleanup(base.CloseIdleConnections)
	eps, err := NewEndpoints(base, urls)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{
		BaseURL: urls[0], TokenID: testTokenID, Secret: testSecret, Backoff: time.Millisecond,
		HTTPClient: &http.Client{Transport: eps, Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, eps
}

func writeGroup(t *testing.T, c *Client) error {
	t.Helper()
	form := map[string][]string{"group": {"g1"}}
	return c.VolumeWrite(t.Context(), http.MethodPost, "/cluster/firewall/groups", form, nil)
}

func TestEndpointsRetryOnlyWhatNeverReachedTheServer(t *testing.T) {
	a := newHostServer(t, ok)
	b := newHostServer(t, ok)
	// localhost is not in the test certificate, so the handshake fails
	// before the request is written.
	wrongName := strings.Replace(a.URL, "127.0.0.1", "localhost", 1)
	for name, first := range map[string]string{"dial refused": deadURL(t), "tls name mismatch": wrongName} {
		t.Run(name, func(t *testing.T) {
			hitsA, hitsB := a.hits.Load(), b.hits.Load()
			c, eps := failoverClient(t, a.Server, first, b.URL)
			if err := writeGroup(t, c); err != nil {
				t.Fatal(err)
			}
			if got := b.hits.Load() - hitsB; got != 1 {
				t.Errorf("second address saw %d requests, want 1", got)
			}
			if got := a.hits.Load() - hitsA; got != 0 {
				t.Errorf("first address saw %d requests through a failed handshake", got)
			}
			if body := <-b.bodies; body != "POST group=g1" {
				t.Errorf("replayed body %q", body)
			}
			if eps.Index() != 1 {
				t.Errorf("index %d, want 1", eps.Index())
			}
		})
	}
}

func TestEndpointsNeverResendASentWrite(t *testing.T) {
	first := newHostServer(t, cut)
	second := newHostServer(t, ok)
	c, eps := failoverClient(t, first.Server, first.URL, second.URL)
	if err := writeGroup(t, c); err == nil {
		t.Fatal("a write cut after it was sent succeeded")
	}
	if first.hits.Load() != 1 || second.hits.Load() != 0 {
		t.Fatalf("hits first=%d second=%d, want 1 and 0", first.hits.Load(), second.hits.Load())
	}
	if eps.Index() != 0 {
		t.Errorf("a failed write moved the index to %d", eps.Index())
	}
}

func TestEndpointsReadAfterCutGoesToTheNextAddress(t *testing.T) {
	first := newHostServer(t, cut)
	second := newHostServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"node":"n2"}]}`)
	})
	c, eps := failoverClient(t, first.Server, first.URL, second.URL)
	nodes, err := c.Nodes(t.Context())
	if err != nil || len(nodes) != 1 || nodes[0].Node != "n2" {
		t.Fatalf("Nodes = %v, %v", nodes, err)
	}
	if eps.Index() != 1 {
		t.Errorf("index %d, want 1", eps.Index())
	}
}

func TestEndpointsUseTheRegisteredAddressesOnly(t *testing.T) {
	srv := newHostServer(t, ok)
	rogue := newHostServer(t, ok)
	redirect := newHostServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, rogue.URL+r.URL.Path, http.StatusTemporaryRedirect)
	})
	c, _ := failoverClient(t, srv.Server, redirect.URL)
	_ = writeGroup(t, c)
	if rogue.hits.Load() != 0 {
		t.Fatal("a redirect carried the request to an address outside the list")
	}
}

func TestEndpointsDeadAddressWithConcurrentCalls(t *testing.T) {
	a := newHostServer(t, ok)
	b := newHostServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"data":[]}`) })
	c, eps := failoverClient(t, a.Server, deadURL(t), b.URL, a.URL)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, err := c.Nodes(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if eps.Index() != 1 {
		t.Errorf("index %d after concurrent failures of one address, want 1", eps.Index())
	}
}

func TestEndpointsAllAddressesDownIsAnError(t *testing.T) {
	ref := newHostServer(t, ok)
	c, _ := failoverClient(t, ref.Server, deadURL(t), deadURL(t))
	if _, err := c.Nodes(t.Context()); err == nil {
		t.Fatal("no address answered and the call succeeded")
	}
}

func TestNewEndpointsRefusesNonOrigins(t *testing.T) {
	base := &http.Transport{}
	for _, bad := range []string{"http://h:8006", "https://h:8006/api", "https://u:p@h:8006", "https://h?x=1", "://"} {
		if _, err := NewEndpoints(base, []string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := NewEndpoints(base, nil); err == nil {
		t.Error("empty list accepted")
	}
}
