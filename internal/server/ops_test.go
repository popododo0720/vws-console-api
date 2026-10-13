package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
	return rec
}

func TestOpsEndpoints(t *testing.T) {
	m := NewMetrics()
	var ready atomic.Bool
	h := opsHandler(m, &ready)
	if rec := get(t, h, "/healthz"); rec.Code != http.StatusOK {
		t.Fatalf("healthz %d", rec.Code)
	}
	if rec := get(t, h, "/readyz"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz before start %d, want 503", rec.Code)
	}
	ready.Store(true)
	if rec := get(t, h, "/readyz"); rec.Code != http.StatusOK {
		t.Fatalf("readyz while serving %d", rec.Code)
	}
	if rec := get(t, h, "/metrics"); rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("metrics %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestMetricsCountRequestsWithTheVWSPrefix(t *testing.T) {
	m := NewMetrics()
	logger := slog.New(slog.DiscardHandler)
	ok := instrument(m, "ec2", wrap(logger, "ec2", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	boom := instrument(m, "s3", wrap(logger, "s3", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})))
	get(t, ok, "/")
	get(t, ok, "/")
	get(t, boom, "/")

	var ready atomic.Bool
	body := get(t, opsHandler(m, &ready), "/metrics").Body.String()
	for _, want := range []string{
		`vws_console_api_http_requests_total{surface="ec2",code="204"} 2`,
		`vws_console_api_http_requests_total{surface="s3",code="500"} 1`,
		`vws_console_api_http_request_duration_seconds_count{surface="ec2"} 2`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q:\n%s", want, body)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		name := strings.TrimPrefix(strings.TrimPrefix(line, "# HELP "), "# TYPE ")
		if !strings.HasPrefix(name, "vws_") {
			t.Errorf("series without the vws_ prefix: %q", line)
		}
	}
}
