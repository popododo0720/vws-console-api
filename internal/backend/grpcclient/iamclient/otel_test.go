package iamclient

import (
	"context"
	"io"
	"net"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-lib/obs"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/service"
)

// observed installs obs with an in-memory span recorder and metric reader,
// as cmd/vws-console-api does with its exporters, and restores the previous
// global providers afterwards so the other tests keep theirs.
func observed(t *testing.T) (*tracetest.SpanRecorder, *sdkmetric.ManualReader) {
	t.Helper()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("VWS_HEALTH_ADDR", "")
	prevTP, prevMP := otel.GetTracerProvider(), otel.GetMeterProvider()
	spans, reader := tracetest.NewSpanRecorder(), sdkmetric.NewManualReader()
	shutdown, err := obs.Setup(t.Context(), obs.ForService(service.Name), obs.WithOverride(func(c *obs.Config) {
		c.MetricReaders = []sdkmetric.Reader{reader}
		c.SpanProcessors = []sdktrace.SpanProcessor{spans}
		c.Sampler, c.LogOutput = "always_on", io.Discard
	}))
	if err != nil {
		t.Fatalf("obs.Setup: %v", err)
	}
	t.Cleanup(func() {
		if err := shutdown(context.WithoutCancel(t.Context())); err != nil {
			t.Errorf("obs shutdown: %v", err)
		}
		otel.SetTracerProvider(prevTP)
		otel.SetMeterProvider(prevMP)
	})
	return spans, reader
}

// dialFake serves a fake vws-iam AuthService on 127.0.0.1 and connects to it
// with Dial, the production path.
func dialFake(t *testing.T) (*Client, *server) {
	t.Helper()
	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{decision: iamv1.Decision_DECISION_ALLOW, authnResult: &iamv1.AuthenticateResponse{
		Account: "123456789012", Arn: "arn:vws:iam::123456789012:user/eng/bob",
		Principal: &iamv1.Principal{
			Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: "arn:vws:iam::123456789012:user/eng/bob",
			Project: "123456789012", UniqueId: "AIDABOB", Resource: "projects/123456789012/users/bob",
		},
	}}
	g := grpc.NewServer()
	iamv1.RegisterAuthServiceServer(g, s)
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Stop)
	c, err := Dial(lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, s
}

const authenticateMethod = "vws.iam.v1.AuthService/Authenticate"

// clientSpan returns the one client span for method, failing otherwise.
func clientSpan(t *testing.T, rec *tracetest.SpanRecorder, method string) sdktrace.ReadOnlySpan {
	t.Helper()
	var found []sdktrace.ReadOnlySpan
	for _, s := range rec.Ended() {
		if s.Name() == method && s.SpanKind() == trace.SpanKindClient {
			found = append(found, s)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d client spans named %s, want 1", len(found), method)
	}
	return found[0]
}

// rpcClientCount returns how many vws.rpc.client.duration samples carry the
// given peer, method and gRPC code.
func rpcClientCount(t *testing.T, reader *sdkmetric.ManualReader, method, code string) uint64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	want := attribute.NewSet(
		attribute.String(obs.LabelService, service.Name), attribute.String(obs.LabelPeer, "iam"),
		attribute.String(obs.LabelRPCMethod, method), attribute.String(obs.LabelGRPCCode, code),
	)
	var n uint64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != obs.MetricRPCClientDuration {
				continue
			}
			h, ok := m.Data.(metricdata.Histogram[float64])
			if !ok {
				t.Fatalf("%s is %T, want a histogram", m.Name, m.Data)
			}
			for _, dp := range h.DataPoints {
				if dp.Attributes.Equals(&want) {
					n += dp.Count
				}
			}
		}
	}
	return n
}

// An IAM call made through Dial leaves a client span joined to the caller's
// trace and one vws.rpc.client.duration sample labelled with vws-iam, the
// method and the outcome.
func TestIAMCallsAreTracedAndMeasured(t *testing.T) {
	rec, reader := observed(t)
	c, _ := dialFake(t)

	ctx, parent := otel.Tracer("test").Start(t.Context(), "http request")
	if _, err := c.Authenticate(ctx, signed); err != nil {
		t.Fatal(err)
	}
	parent.End()

	span := clientSpan(t, rec, authenticateMethod)
	if span.SpanContext().TraceID() != parent.SpanContext().TraceID() {
		t.Fatalf("client span trace %s, caller trace %s", span.SpanContext().TraceID(), parent.SpanContext().TraceID())
	}
	if span.Parent().SpanID() != parent.SpanContext().SpanID() {
		t.Fatal("the client span is not a child of the caller's span")
	}
	if got := rpcClientCount(t, reader, authenticateMethod, codes.OK.String()); got != 1 {
		t.Fatalf("%d OK samples of %s for %s, want 1", got, obs.MetricRPCClientDuration, authenticateMethod)
	}
}

// A failed IAM call is recorded with its gRPC code on both the span and the
// metric, so failures are visible without logs.
func TestFailedIAMCallsAreTracedAndMeasured(t *testing.T) {
	rec, reader := observed(t)
	c, s := dialFake(t)
	s.authnErr = status.Error(codes.PermissionDenied, "signature does not match")

	if _, err := c.Authenticate(t.Context(), signed); err == nil {
		t.Fatal("Authenticate succeeded against a denying vws-iam")
	}

	span := clientSpan(t, rec, authenticateMethod)
	var code string
	for _, kv := range span.Attributes() {
		if kv.Key == "rpc.response.status_code" {
			code = kv.Value.AsString()
		}
	}
	if code != "PERMISSION_DENIED" || span.Status().Code != otelcodes.Error {
		t.Fatalf("span status %v, rpc.response.status_code %q; attributes %v", span.Status(), code, span.Attributes())
	}
	if got := rpcClientCount(t, reader, authenticateMethod, codes.PermissionDenied.String()); got != 1 {
		t.Fatalf("%d PermissionDenied samples for %s, want 1", got, authenticateMethod)
	}
	if got := rpcClientCount(t, reader, authenticateMethod, codes.OK.String()); got != 0 {
		t.Fatalf("%d OK samples for a failed call", got)
	}
}
