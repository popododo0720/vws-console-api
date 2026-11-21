package regionapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestClientDeregister(t *testing.T) {
	var got string
	var failure error
	srv := httptest.NewTLSServer(WithDeregistration(func(_ context.Context, data json.RawMessage) error {
		got = string(data)
		return failure
	}, http.NotFoundHandler()))
	defer srv.Close()
	config := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	config.Certificates = srv.TLS.Certificates
	client, err := NewClient(srv.URL, config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Deregister(t.Context(), "pve-test-1"); err != nil || got != `{"region":"pve-test-1"}` {
		t.Fatalf("deregister: %v, body %q", err, got)
	}
	failure = errors.New("boom")
	if err := client.Deregister(t.Context(), "pve-test-1"); err == nil ||
		resource.RegionFailureMessage(err) != "deregistration failed" {
		t.Fatalf("failure: %v", err)
	}
}
