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
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/popododo0720/vws-lib/obs"
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

func TestClientRequestIDIsValidated(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("VWS_HEALTH_ADDR", "")
	var logs bytes.Buffer
	shutdown, err := obs.Setup(t.Context(), obs.ForService(service.Name),
		obs.WithOverride(func(c *obs.Config) { c.LogOutput = &logs }))
	if err != nil {
		t.Fatalf("obs.Setup: %v", err)
	}
	t.Cleanup(func() {
		if err := shutdown(context.WithoutCancel(t.Context())); err != nil {
			t.Errorf("obs shutdown: %v", err)
		}
	})

	const validID = "req-0123456789abcdef"
	tests := []struct {
		name string
		id   string
		keep bool
	}{
		{name: "valid", id: validID, keep: true},
		{name: "64 bytes", id: strings.Repeat("a", 64), keep: true},
		{name: "longer than 64 bytes", id: strings.Repeat("a", 65)},
		{name: "newline", id: "req-0123456789abcde\nf"},
		{name: "space", id: "req-0123456789abcde f"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := logs.Len()
			var seen string
			ec2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = r.Header.Get(httpobs.RequestIDHeader)
				w.WriteHeader(http.StatusOK)
			})
			h := surfaceHandler(slog.Default(), NewMetrics(), Surface{Name: "ec2", Handler: ec2})
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.Header.Set(httpobs.RequestIDHeader, tt.id)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			got := rec.Header().Get(httpobs.RequestIDHeader)
			if seen != got {
				t.Fatalf("handler saw request id %q, response header %q", seen, got)
			}
			if tt.keep {
				if got != tt.id {
					t.Fatalf("response request id %q, want %q", got, tt.id)
				}
			} else {
				if got == tt.id {
					t.Fatalf("unsafe request id %q was kept", got)
				}
				if !isGeneratedRequestID(got) {
					t.Fatalf("replacement request id %q is not 16 lowercase hex characters", got)
				}
			}
			if id := requestLogID(t, logs.String()[start:]); id != got {
				t.Fatalf("log request_id %q, response header %q", id, got)
			}
		})
	}
}

// requestLogID returns the request_id of the first "request" log line.
func requestLogID(t *testing.T, logs string) string {
	t.Helper()
	for _, line := range strings.Split(logs, "\n") {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) != nil || entry["msg"] != "request" {
			continue
		}
		id, ok := entry["request_id"].(string)
		if !ok {
			t.Fatalf("request log line has no request_id: %s", line)
		}
		return id
	}
	t.Fatalf("no request log line: %s", logs)
	return ""
}

// isGeneratedRequestID reports whether id has the 16 lowercase hex characters
// obs.NewRequestID makes.
func isGeneratedRequestID(id string) bool {
	if len(id) != 16 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
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

// TestHTTPMiddlewareStartsARootServerSpan sends an EC2 Query request through
// the chain Serve builds for a surface. The handler must run inside a new root
// server span: the inbound traceparent is dropped at the boundary, so the
// traceparent an outbound call injects from the handler context carries the
// local trace id, not the caller's, and a caller cannot force sampling through
// the parent-based sampler. grpcclient's TestClientPropagatesTraceparent
// covers the gRPC hop.
func TestHTTPMiddlewareStartsARootServerSpan(t *testing.T) {
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

	var got trace.SpanContext
	var inboundState string
	outbound := http.Header{}
	ec2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = trace.SpanContextFromContext(r.Context())
		inboundState = r.Header.Get("tracestate")
		otel.GetTextMapPropagator().Inject(r.Context(), propagation.HeaderCarrier(outbound))
		w.WriteHeader(http.StatusOK)
	})
	h := surfaceHandler(slog.New(slog.DiscardHandler), NewMetrics(), Surface{Name: "ec2", Handler: ec2})

	const inboundTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
	body := strings.NewReader("Action=DescribeInstances&Version=2016-11-15")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("traceparent", "00-"+inboundTrace+"-00f067aa0ba902b7-01")
	req.Header.Set("tracestate", "vendor=value")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if inboundState != "" {
		t.Fatalf("handler saw inbound tracestate %q", inboundState)
	}
	if !got.IsValid() || got.IsRemote() {
		t.Fatalf("the handler ran without a local server span: %+v", got)
	}
	localTrace := got.TraceID().String()
	if localTrace == inboundTrace {
		t.Fatalf("server span continued the inbound trace id %s", inboundTrace)
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
	parent := outbound.Get("traceparent")
	if !strings.Contains(parent, localTrace) || !strings.Contains(parent, got.SpanID().String()) {
		t.Fatalf("outbound traceparent %q does not carry trace id %s and span %s", parent, localTrace, got.SpanID())
	}
	if strings.Contains(parent, inboundTrace) {
		t.Fatalf("outbound traceparent %q carries the inbound trace id %s", parent, inboundTrace)
	}
}

// TestCleanStopReturnsNilWhenTheDrainBoundExpires proves a stop the caller
// asked for is not reported as a deadline error when a connection outlives the
// five second drain. An idle connection that never sends a request is the
// common case: http.Server.Shutdown leaves it in StateNew for its whole five
// second window (https://go.dev/issue/22682). The handler here holds the bound,
// so the expiry is deterministic.
func TestCleanStopReturnsNilWhenTheDrainBoundExpires(t *testing.T) {
	const attempts = 5
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err = drainBoundExpires(t); !errors.Is(err, syscall.EADDRINUSE) {
			break
		}
	}
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

// drainBoundExpires starts Serve on a free address, holds one request until
// the drain bound expires, and stops the server. The caller retries the case
// when another process takes the address between listen and Serve.
func drainBoundExpires(t *testing.T) error {
	t.Helper()
	const startTimeout = 10 * time.Second
	var log bytes.Buffer
	entered := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	})
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- Serve(ctx, Options{
			Logger:   slog.New(slog.NewTextHandler(&log, nil)),
			Surfaces: []Surface{{Name: "test", Addr: addr, Handler: handler}},
		})
	}()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		deadline := time.Now().Add(startTimeout)
		for {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr, nil)
			if err != nil {
				return
			}
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				return
			}
			select {
			case <-entered:
				return
			default:
			}
			if ctx.Err() != nil || time.Now().After(deadline) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	select {
	case <-entered:
	case err := <-errc:
		cancel()
		if err == nil {
			return errors.New("Serve stopped before the request ran")
		}
		return err
	case <-time.After(startTimeout):
		cancel()
		return errors.New("handler did not start")
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			close(release)
			<-clientDone
			return err
		}
		// Read the warning before the handler returns and the request access
		// log writes to the same buffer.
		got := log.String()
		close(release)
		<-clientDone
		if !strings.Contains(got, "shutdown drain bound expired") ||
			!strings.Contains(got, "context deadline exceeded") {
			return errors.New("the drain expiry was not logged")
		}
		return nil
	case <-time.After(15 * time.Second):
		close(release)
		return errors.New("Serve did not return")
	}
}
