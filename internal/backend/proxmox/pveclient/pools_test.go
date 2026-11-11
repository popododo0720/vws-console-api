package pveclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoolReadsAndClassifiesFailures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		message  string
		exists   bool
		wantErr  bool
		attempts int32
	}{
		{"present", 200, "", true, false, 1},
		{"absent 404", 404, "", false, false, 1},
		{"absent 500", 500, "pool 'project' does not exist", false, false, 1},
		{"forbidden", 403, "Permission check failed", false, true, 1},
		{"unauthorized", 401, "authentication failure", false, true, 1},
		{"unavailable", 503, "service unavailable", false, true, 1 + MaxRetries},
		{"unrelated 500", 500, "permission service failed", false, true, 1 + MaxRetries},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts atomic.Int32
			c, rt := newClient(t, func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/api2/json/pools/project" ||
					r.Header.Get("Authorization") != "PVEAPIToken="+testTokenID+"="+testSecret {
					t.Errorf("pool request: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, `{"data":{"members":[]},"message":%q}`, tc.message)
			}, nil)
			got, err := c.Pool(t.Context(), "project")
			if got != tc.exists || (err != nil) != tc.wantErr || attempts.Load() != tc.attempts ||
				rt.missed.Load() != 0 {
				t.Fatalf("exists=%t err=%v attempts=%d missed deadlines=%d",
					got, err, attempts.Load(), rt.missed.Load())
			}
		})
	}
}

func TestPoolRetryAndCanceledRead(t *testing.T) {
	var attempts atomic.Int32
	c, _ := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, `{"data":{"members":[]}}`)
	}, nil)
	for range 2 {
		if exists, err := c.Pool(t.Context(), "project"); err != nil || !exists {
			t.Fatalf("pool retry: %t %v", exists, err)
		}
	}
	if attempts.Load() != 3 {
		t.Fatalf("retry and repeat sent %d requests, want 3", attempts.Load())
	}
	ctx, cancel := context.WithDeadline(t.Context(), time.Unix(0, 0))
	defer cancel()
	if _, err := c.Pool(ctx, "project"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired read: %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatal("expired read reached PVE")
	}
}

func TestBadPoolIDsNeverReachPVE(t *testing.T) {
	var requests atomic.Int32
	c, _ := newClient(t, func(http.ResponseWriter, *http.Request) { requests.Add(1) }, nil)
	for _, pool := range []string{
		"", ".", "..", "../access", "a/b", "%2F", "a?b", "a#b", "a\x00b", "a b", "-a", strings.Repeat("a", 65),
	} {
		if exists, err := c.Pool(t.Context(), pool); err == nil || exists {
			t.Fatalf("bad pool %q: %t %v", pool, exists, err)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("invalid pool reached PVE")
	}
}

func TestPoolRefusesNullSuccess(t *testing.T) {
	c, _ := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"data":null}`)
	}, nil)
	if exists, err := c.Pool(t.Context(), "project"); exists || err == nil {
		t.Fatalf("null pool response: %t %v", exists, err)
	}
}
