package kubestore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/rest"

	"github.com/popododo0720/vws-console-api/internal/backend/launch"
)

const testKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// status writes a Kubernetes Status answer.
func status(w http.ResponseWriter, code int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","code":%d,"reason":%q}`, code, reason)
}

// stall holds a request unanswered until the client gives up on it. The
// body is read first, so the server notices the client closing.
func stall(r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	select {
	case <-r.Context().Done():
	case <-time.After(3 * time.Second):
	}
}

func serve(t *testing.T, h func(n int64, w http.ResponseWriter, r *http.Request)) (*rest.Config, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h(calls.Add(1), w, r)
	}))
	t.Cleanup(srv.Close)
	return &rest.Config{Host: srv.URL}, &calls
}

// TestStalledRequestIsRetried: a request that times out on the wire is
// tried again, and the call succeeds once the API server answers.
func TestStalledRequestIsRetried(t *testing.T) {
	cfg, calls := serve(t, func(n int64, w http.ResponseWriter, r *http.Request) {
		if n == 1 {
			stall(r)
			return
		}
		status(w, http.StatusNotFound, "NotFound")
	})
	s, err := newStore(cfg, "vws-system", 100*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _, found, err := s.Load(context.Background(), testKey)
	if err != nil || found || calls.Load() != 2 {
		t.Fatalf("found %v err %v after %d calls", found, err, calls.Load())
	}
}

// TestExpiredCallerDeadlineIsNotRetried: a caller that stopped waiting gets
// its error after one request, not after the retries.
func TestExpiredCallerDeadlineIsNotRetried(t *testing.T) {
	cfg, calls := serve(t, func(_ int64, _ http.ResponseWriter, r *http.Request) { stall(r) })
	s, err := newStore(cfg, "vws-system", 5*time.Second, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, _, _, err := s.Load(ctx, testKey); err == nil || calls.Load() != 1 {
		t.Fatalf("err %v after %d calls", err, calls.Load())
	}
}

// TestRetryAfterStaysInTheCallBudget: client-go retries a 429 that carries
// Retry-After on its own; the whole call still ends within its budget.
func TestRetryAfterStaysInTheCallBudget(t *testing.T) {
	cfg, calls := serve(t, func(_ int64, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "1")
		status(w, http.StatusTooManyRequests, "TooManyRequests")
	})
	const budget = 1500 * time.Millisecond
	s, err := newStore(cfg, "vws-system", time.Second, budget)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, _, _, err = s.Load(context.Background(), testKey)
	if took := time.Since(start); err == nil || took > budget+500*time.Millisecond {
		t.Fatalf("err %v after %v and %d calls", err, took, calls.Load())
	}
}

// TestLostCreateResponseIsExists: a create applied on the server whose
// answer was lost is retried, and the retry's AlreadyExists is ErrExists,
// which the tracker resolves by loading the record.
func TestLostCreateResponseIsExists(t *testing.T) {
	cfg, calls := serve(t, func(n int64, w http.ResponseWriter, r *http.Request) {
		if n == 1 {
			stall(r)
			return
		}
		status(w, http.StatusConflict, "AlreadyExists")
	})
	s, err := newStore(cfg, "vws-system", 100*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(context.Background(), launch.Record{Key: testKey}); !errors.Is(err, launch.ErrExists) ||
		calls.Load() != 2 {
		t.Fatalf("err %v after %d calls", err, calls.Load())
	}
}

// TestObjectLimitCountsTheWholeConfigMap pins the size check at the byte:
// the whole ConfigMap plus the server metadata headroom may reach the limit
// and not pass it.
func TestObjectLimitCountsTheWholeConfigMap(t *testing.T) {
	s := &Store{namespace: "vws-system"}
	size := func(rec launch.Record) int {
		cm, err := s.configMap(rec, "")
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(cm)
		if err != nil {
			t.Fatal(err)
		}
		return len(b)
	}
	rec := launch.Record{Key: testKey}
	// Each fingerprint byte is one byte in the record and, escaped as a JSON
	// string inside the ConfigMap, one byte in the object.
	fill := MaxRecordBytes - metadataHeadroom - size(rec)
	rec.Fingerprint = strings.Repeat("f", fill)
	if got := size(rec) + metadataHeadroom; got != MaxRecordBytes {
		t.Fatalf("at the limit the object is %d bytes", got)
	}
	rec.Fingerprint += "f"
	if _, err := s.configMap(rec, ""); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("one byte over the limit: %v", err)
	}
}

// TestTransientAPIErrorsAreRetriedAndBounded: a 429 or 503 is tried again
// with backoff until the API server answers, at most 4 times.
func TestTransientAPIErrorsAreRetriedAndBounded(t *testing.T) {
	for failures, want := range map[int64]int64{2: 3, 100: 4} {
		cfg, calls := serve(t, func(n int64, w http.ResponseWriter, _ *http.Request) {
			switch {
			case n > failures:
				status(w, http.StatusNotFound, "NotFound")
			case n%2 == 1:
				status(w, http.StatusTooManyRequests, "TooManyRequests")
			default:
				status(w, http.StatusServiceUnavailable, "ServiceUnavailable")
			}
		})
		s, err := New(cfg, "vws-system")
		if err != nil {
			t.Fatal(err)
		}
		_, _, found, err := s.Load(context.Background(), testKey)
		if (err != nil) != (failures > 4) || found || calls.Load() != want {
			t.Fatalf("%d failures: found %v err %v after %d calls", failures, found, err, calls.Load())
		}
	}
	if _, err := New(&rest.Config{Host: "http://127.0.0.1:1"}, ""); err == nil {
		t.Fatal("empty namespace accepted")
	}
}
