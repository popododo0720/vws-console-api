package grpcclient

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/popododo0720/vws-lib/obs"

	"github.com/popododo0720/vws-console-api/internal/service"
)

// TestClientPropagatesTraceparent proves that a gRPC call made with a span in
// its context carries the W3C traceparent and the request id to the server.
// The server is a fake that records the metadata it received.
func TestClientPropagatesTraceparent(t *testing.T) {
	previous := otel.GetTracerProvider()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		_ = tp.Shutdown(context.Background())
	})

	lis := bufconn.Listen(1 << 20)
	var mu sync.Mutex
	var received metadata.MD
	record := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		mu.Lock()
		received = md.Copy()
		mu.Unlock()
		return handler(ctx, req)
	}
	srv := grpc.NewServer(grpc.UnaryInterceptor(record))
	healthpb.RegisterHealthServer(srv, healthServer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	dialer := grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	})
	conn, err := grpc.NewClient("passthrough:///trace-test", append(dialOptionsFor(service.Name, "compute"), dialer)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx := obs.WithRequestID(t.Context(), "req-abc")
	ctx, span := otel.Tracer("test").Start(ctx, "http request")
	defer span.End()
	if _, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	traceparent := received.Get("traceparent")
	if len(traceparent) == 0 {
		t.Fatalf("no traceparent in %v", received)
	}
	if !strings.Contains(traceparent[0], span.SpanContext().TraceID().String()) {
		t.Fatalf("traceparent %q does not carry trace id %s", traceparent[0], span.SpanContext().TraceID())
	}
	if got := received.Get("x-request-id"); len(got) == 0 || got[0] != "req-abc" {
		t.Fatalf("x-request-id %v", got)
	}
}

type healthServer struct {
	healthpb.UnimplementedHealthServer
}

func (healthServer) Check(context.Context, *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}
