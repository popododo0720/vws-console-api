package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"github.com/popododo0720/vws-lib/obs"
	"github.com/popododo0720/vws-lib/obs/grpcobs"
	"github.com/popododo0720/vws-lib/obs/httpobs"
	"github.com/popododo0720/vws-lib/obs/report"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/service"
)

func TestInternalErrorIsLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cause := errors.New(`bad operation name "projects/a/operations/op-zzzz"`)
	h := wrap(logger, "ec2", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		err := resource.Internal(cause)
		RecordFailure(w, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "bad operation name") {
		t.Fatalf("cause leaked: %s", rec.Body)
	}
	if !strings.Contains(buf.String(), "request failed") || !strings.Contains(buf.String(), "bad operation name") {
		t.Fatalf("log %s", buf.String())
	}
}

func TestListenerBounds(t *testing.T) {
	srv := newHTTPServer(":0", http.NewServeMux())
	if srv.ReadHeaderTimeout == 0 || srv.ReadTimeout == 0 || srv.WriteTimeout == 0 || srv.IdleTimeout == 0 {
		t.Fatalf("unbounded listener: header %s read %s write %s idle %s", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
}

func TestPanicIsABare500(t *testing.T) {
	var buf bytes.Buffer
	var panics atomic.Int64
	report.Configure(report.Sink{
		Logger:     slog.New(slog.NewJSONHandler(&buf, nil)),
		CountPanic: func(context.Context) { panics.Add(1) },
	})
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	h := wrap(logger, "s3", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("secret-key-material")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Body.String(); got != "internal error\n" {
		t.Fatalf("body %q", got)
	}
	if strings.Contains(rec.Body.String(), "secret-key-material") {
		t.Fatalf("panic value leaked: %s", rec.Body)
	}
	if got := panics.Load(); got != 1 {
		t.Fatalf("report.Panic called %d times, want 1", got)
	}
	if !strings.Contains(buf.String(), "secret-key-material") {
		t.Fatalf("panic not logged: %s", buf.String())
	}
}

func TestRequestIDIsTheSameInLogAndResponse(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("VWS_HEALTH_ADDR", "")
	var buf bytes.Buffer
	shutdown, err := obs.Setup(t.Context(), obs.ForService(service.Name),
		obs.WithOverride(func(c *obs.Config) { c.LogOutput = &buf }))
	if err != nil {
		t.Fatalf("obs.Setup: %v", err)
	}
	t.Cleanup(func() {
		if err := shutdown(context.WithoutCancel(t.Context())); err != nil {
			t.Errorf("obs shutdown: %v", err)
		}
	})

	var seen string
	h := wrap(slog.Default(), "ec2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get(httpobs.RequestIDHeader)
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil))
	id := rec.Header().Get(httpobs.RequestIDHeader)
	if id == "" {
		t.Fatal("no request id header")
	}
	if seen != id {
		t.Fatalf("handler saw request id %q, want %q", seen, id)
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) != nil || entry["msg"] != "request" {
			continue
		}
		if got := entry["request_id"]; got != id {
			t.Fatalf("log request_id %v, header %q", got, id)
		}
		return
	}
	t.Fatalf("no request log line: %s", buf.String())
}

func TestWriteFailureIsLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	h := wrap(logger, "ec2", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		RecordFailure(w, errors.New("client went away"))
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if !strings.Contains(buf.String(), `level=WARN msg="response failed"`) || !strings.Contains(buf.String(), "client went away") {
		t.Fatalf("log %s", buf.String())
	}
}

// TestHTTPMiddlewareStartsAServerSpan sends an EC2 Query request through the
// chain Serve builds for a surface. The handler must run inside a server span
// that continues the caller's traceparent, and a gRPC call made from that
// handler must carry the same trace id to the backend.
func TestHTTPMiddlewareStartsAServerSpan(t *testing.T) {
	previous := otel.GetTracerProvider()
	previousPropagator := otel.GetTextMapPropagator()
	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(spans))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		otel.SetTextMapPropagator(previousPropagator)
		_ = tp.Shutdown(context.Background())
	})

	backend := newTraceBackend(t)
	var got trace.SpanContext
	ec2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = trace.SpanContextFromContext(r.Context())
		if _, err := healthpb.NewHealthClient(backend.conn).Check(r.Context(), &healthpb.HealthCheckRequest{}); err != nil {
			t.Errorf("backend call: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})
	h := surfaceHandler(slog.New(slog.DiscardHandler), NewMetrics(), Surface{Name: "ec2", Handler: ec2})

	const inboundTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
	body := strings.NewReader("Action=DescribeInstances&Version=2016-11-15")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("traceparent", "00-"+inboundTrace+"-00f067aa0ba902b7-01")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if !got.IsValid() || got.IsRemote() {
		t.Fatalf("the handler ran without a local server span: %+v", got)
	}
	if got.TraceID().String() != inboundTrace {
		t.Fatalf("server span trace id %s, inbound %s", got.TraceID(), inboundTrace)
	}
	var server bool
	for _, s := range spans.Ended() {
		if s.SpanContext().SpanID() == got.SpanID() && s.SpanKind() == trace.SpanKindServer {
			server = true
		}
	}
	if !server {
		t.Fatal("no ended server-kind span matches the handler span")
	}
	if tp := backend.traceparent(); !strings.Contains(tp, inboundTrace) {
		t.Fatalf("backend traceparent %q does not carry trace id %s", tp, inboundTrace)
	}
}

type traceBackend struct {
	conn     *grpc.ClientConn
	mu       sync.Mutex
	received metadata.MD
}

// newTraceBackend is a fake gRPC backend that records the metadata of the
// last call. The client uses the same vws-lib dial options as grpcclient.
func newTraceBackend(t *testing.T) *traceBackend {
	t.Helper()
	b := &traceBackend{}
	lis := bufconn.Listen(1 << 20)
	record := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		b.mu.Lock()
		b.received = md.Copy()
		b.mu.Unlock()
		return handler(ctx, req)
	}
	srv := grpc.NewServer(grpc.UnaryInterceptor(record))
	healthpb.RegisterHealthServer(srv, health.NewServer())
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	opts := append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
	}, grpcobs.ClientOptions(service.Name, "compute")...)
	conn, err := grpc.NewClient("passthrough:///trace-backend", opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	b.conn = conn
	return b
}

func (b *traceBackend) traceparent() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if v := b.received.Get("traceparent"); len(v) > 0 {
		return v[0]
	}
	return ""
}
