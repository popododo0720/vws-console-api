package regionapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func deregisterRequest(t *testing.T, h http.Handler, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, deregisterPath, strings.NewReader(body)))
	return rec
}

func TestDeregistrationRoute(t *testing.T) {
	const secret = "upstream-token-canary"
	var got []string
	var failure error
	h := WithDeregistration(func(_ context.Context, data json.RawMessage) error {
		got = append(got, string(data))
		return failure
	}, http.NotFoundHandler())
	if rec := deregisterRequest(t, h, http.MethodPost, `{"region":"pve-test-1"}`); rec.Code != http.StatusOK ||
		strings.TrimSpace(rec.Body.String()) != "{}" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("success: %d %s %v", rec.Code, rec.Body, rec.Header())
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		rec := deregisterRequest(t, h, method, "")
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s reached the route: %d", method, rec.Code)
		}
	}
	failure = resource.Invalid("region", "deregistration is for another region than this instance")
	if rec := deregisterRequest(t, h, http.MethodPost, `{}`); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "another region") {
		t.Fatalf("invalid: %d %s", rec.Code, rec.Body)
	}
	failure = errors.New("remove registration: " + secret)
	rec := deregisterRequest(t, h, http.MethodPost, `{"region":"`+secret+`"}`)
	var body errorBody
	if rec.Code != http.StatusServiceUnavailable || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body.Error == nil ||
		body.Error.Message != "deregistration failed" || strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("internal failure: %d %s", rec.Code, rec.Body)
	}
	calls := len(got)
	rec = deregisterRequest(t, h, http.MethodPost, strings.Repeat("x", maxDeregisterBytes+1))
	if rec.Code != http.StatusRequestEntityTooLarge || len(got) != calls {
		t.Fatalf("oversized body reached the daemon: %d", rec.Code)
	}
}

func TestDeregistrationRequiresTheGlobalClientCertificate(t *testing.T) {
	var calls atomic.Int32
	var failure error
	h := WithDeregistration(func(context.Context, json.RawMessage) error {
		calls.Add(1)
		return failure
	}, http.NotFoundHandler())
	client, anonymous, base := serveConnectionTest(t, h)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+deregisterPath,
		strings.NewReader(`{"region":"pve-test-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := anonymous.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("a client without a certificate got status %d", resp.StatusCode)
	}
	if calls.Load() != 0 {
		t.Fatal("an unauthenticated request reached the daemon")
	}
	deregister := func() error {
		var result struct{}
		return client.do(t.Context(), http.MethodPost, deregisterPath,
			[]byte(`{"region":"pve-test-1","generation":7}`), &result)
	}
	if err := deregister(); err != nil || calls.Load() != 1 {
		t.Fatalf("deregister: %v, calls %d", err, calls.Load())
	}
	failure = errors.New("boom")
	if err := deregister(); err == nil || resource.AsError(err).Message != "deregistration failed" {
		t.Fatalf("failure: %v", err)
	}
}

// A daemon that serves the fence route enforces generations; one without
// WithDeregistration answers 404.
func TestFenceRouteAdvertisesTheCapability(t *testing.T) {
	h := WithDeregistration(func(context.Context, json.RawMessage) error { return nil }, http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, fencePath, nil))
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"generation":true}` ||
		rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("fence: %d %s %v", rec.Code, rec.Body, rec.Header())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, fencePath, nil))
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST reached the fence route: %d", rec.Code)
	}
}
