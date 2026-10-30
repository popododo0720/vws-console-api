package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/popododo0720/vws-lib/obs"
	"github.com/popododo0720/vws-lib/obs/httpobs"

	"github.com/popododo0720/vws-console-api/internal/service"
)

func TestHTTPServerMetrics(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("VWS_HEALTH_ADDR", "")
	reader := sdkmetric.NewManualReader()
	shutdown, err := obs.Setup(t.Context(), obs.ForService(service.Name), obs.WithOverride(func(c *obs.Config) {
		c.MetricReaders = []sdkmetric.Reader{reader}
		c.LogOutput = io.Discard
	}))
	if err != nil {
		t.Fatalf("obs.Setup: %v", err)
	}
	t.Cleanup(func() {
		if err := shutdown(context.WithoutCancel(t.Context())); err != nil {
			t.Errorf("obs shutdown: %v", err)
		}
	})

	h := httpobs.Middleware(service.Name, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"vws.http.server.requests": false, "vws.http.server.duration": false}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if _, ok := want[m.Name]; ok {
				want[m.Name] = true
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("metric %s was not recorded", name)
		}
	}
}

func TestForbiddenMetricLabelsPanic(t *testing.T) {
	if !panics(func() { _ = obs.Attrs("resource_id", "i-0123456789abcdef0") }) {
		t.Fatal("resource_id was accepted as a metric label")
	}
	if !panics(func() { _ = obs.Attrs("request_id", "req-1") }) {
		t.Fatal("request_id was accepted as a metric label")
	}
	_ = obs.Attrs("action", "DescribeInstances", "aws_code", "InvalidInstanceID.NotFound")
}

func panics(f func()) (panicked bool) {
	defer func() { panicked = recover() != nil }()
	f()
	return
}
