package ec2query

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/popododo0720/vws-lib/obs"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/service"
)

// TestAWSErrorMetricCarriesActionAndCode proves the EC2 error path counts the
// answer with the action and the AWS code, and with no request-scoped label.
func TestAWSErrorMetricCarriesActionAndCode(t *testing.T) {
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

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/?Action=DescribeInstances", nil)
	req.Header.Set("X-Request-Id", "req-1")
	writeErr(httptest.NewRecorder(), req, resource.NotFound(resource.KindInstance, "i-0123456789abcdef0"))

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "vws.aws.errors" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok || len(sum.DataPoints) == 0 {
				t.Fatalf("%s has no data points", m.Name)
			}
			for _, dp := range sum.DataPoints {
				action, _ := dp.Attributes.Value("action")
				code, _ := dp.Attributes.Value("aws_code")
				if action.AsString() != "DescribeInstances" || code.AsString() != "InvalidInstanceID.NotFound" {
					t.Fatalf("labels action=%q aws_code=%q", action.AsString(), code.AsString())
				}
				for _, forbidden := range []string{"request_id", "resource_id", "trace_id"} {
					if _, ok := dp.Attributes.Value(attribute.Key(forbidden)); ok {
						t.Fatalf("label %q is forbidden", forbidden)
					}
				}
			}
			return
		}
	}
	t.Fatal("vws.aws.errors was not recorded")
}
