package proxmox

import (
	"context"
	"io"
	"testing"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/popododo0720/vws-lib/obs"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/service"
)

func TestInventoryUndecodableConfigIsReported(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("VWS_HEALTH_ADDR", "")
	previousTracer, previousMeter := otel.GetTracerProvider(), otel.GetMeterProvider()
	reader := sdkmetric.NewManualReader()
	shutdown, err := obs.Setup(t.Context(), obs.ForService(service.Name), obs.WithOverride(func(c *obs.Config) {
		c.MetricReaders = []sdkmetric.Reader{reader}
		c.LogOutput = io.Discard
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := shutdown(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
		otel.SetTracerProvider(previousTracer)
		otel.SetMeterProvider(previousMeter)
	})
	s := inventoryScenario()
	s.VMs = append(s.VMs, pvefake.VM{
		VMID: 101, Node: "pve1", Pool: "123456789012", Status: "running",
		Config: map[string]string{"memory": "invalid"},
	})
	b, _ := networkBackend(t, s, RegionConfig{})
	for want := int64(1); want <= 2; want++ {
		page, err := b.DescribeInstances(t.Context(), inventoryScope(), resource.InstanceQuery{})
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != powerID(t) {
			t.Fatalf("valid VM lost: %+v, %v", page, err)
		}
		var metrics metricdata.ResourceMetrics
		if err := reader.Collect(t.Context(), &metrics); err != nil {
			t.Fatal(err)
		}
		var count int64
		for _, scope := range metrics.ScopeMetrics {
			for _, m := range scope.Metrics {
				if m.Name != obs.MetricErrors {
					continue
				}
				sum, ok := m.Data.(metricdata.Sum[int64])
				if !ok {
					t.Fatalf("error metric has type %T", m.Data)
				}
				for _, point := range sum.DataPoints {
					count += point.Value
				}
			}
		}
		if count != want {
			t.Fatalf("error count = %d, want %d", count, want)
		}
	}
}
