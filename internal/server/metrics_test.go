package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/popododo0720/vws-lib/obs"

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

	ec2 := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	h := surfaceHandler(slog.New(slog.DiscardHandler), NewMetrics(), Surface{Name: "ec2", Handler: ec2})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/i-0123456789abcdef0", strings.NewReader("Action=DescribeInstances&Version=2016-11-15"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(httptest.NewRecorder(), req)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"vws.http.server.requests": false, "vws.http.server.duration": false}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if _, ok := want[m.Name]; !ok {
				continue
			}
			for _, set := range dataPointAttrs(m.Data) {
				route, _ := set.Value(obs.LabelRoute)
				svc, _ := set.Value(obs.LabelService)
				class, _ := set.Value(obs.LabelStatusClass)
				if route.AsString() == "/" && svc.AsString() == service.Name && class.AsString() == "4xx" {
					want[m.Name] = true
				}
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("metric %s was not recorded with route \"/\", service %q, status 4xx: %+v", name, service.Name, rm.ScopeMetrics)
		}
	}
}

func dataPointAttrs(data metricdata.Aggregation) []attribute.Set {
	var sets []attribute.Set
	switch d := data.(type) {
	case metricdata.Sum[int64]:
		for _, p := range d.DataPoints {
			sets = append(sets, p.Attributes)
		}
	case metricdata.Sum[float64]:
		for _, p := range d.DataPoints {
			sets = append(sets, p.Attributes)
		}
	case metricdata.Histogram[float64]:
		for _, p := range d.DataPoints {
			sets = append(sets, p.Attributes)
		}
	case metricdata.Histogram[int64]:
		for _, p := range d.DataPoints {
			sets = append(sets, p.Attributes)
		}
	}
	return sets
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
