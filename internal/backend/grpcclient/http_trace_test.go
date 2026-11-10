package grpcclient

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

// TestOneTraceCrossesFromHTTPToTheBackend sends a signed EC2
// DescribeKeyPairs through server.Serve, the EC2 Query surface and the kernel
// to a client from Dial, wired as cmd/vws-console-api wires them (issue
// #201). The compute service is a gRPC server that records the metadata it
// receives. One trace must hold the inbound HTTP server span and the outbound
// gRPC client span as its child, and the compute service must receive that
// client span in its traceparent, with the request id the answer carries.
func TestOneTraceCrossesFromHTTPToTheBackend(t *testing.T) {
	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(spans))
	previous, previousPropagator := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		otel.SetTextMapPropagator(previousPropagator)
		_ = tp.Shutdown(context.Background())
	})

	keys := &recordingKeys{}
	computeAddr := serveKeys(t, keys)
	client, err := Dial(t.Context(), Addrs{Compute: computeAddr, Storage: computeAddr, Network: computeAddr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	cred := sigv4.Credential{AccessKey: "AKIDTRACE", Secret: "trace-secret", Account: account}
	root := iam.NewStatic(cred.AccessKey, cred.Secret, account)
	verifier := sigv4.Verifier{Service: sigv4.ServiceEC2, Regions: backend.DefaultRegions(), Auth: iam.Authenticator(root)}
	ec2 := ec2query.New(ec2query.Config{
		Service:    cloud.New(cloud.Config{Backends: client.Set(), Audit: slog.New(slog.DiscardHandler)}),
		Verifier:   sigv4.NewVerifier(verifier),
		Authorizer: root,
	})
	addr := serveEC2(t, ec2)

	form := url.Values{"Action": {"DescribeKeyPairs"}, "Version": {"2016-11-15"}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+addr+"/",
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := sigv4.Sign(req, cred, sigv4.ServiceEC2, resource.RegionName, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	res, err := (&http.Client{Transport: &http.Transport{}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("DescribeKeyPairs %d %v %s", res.StatusCode, err, body)
	}
	requestID := regexp.MustCompile(`<requestId>([^<]+)</requestId>`).FindSubmatch(body)
	if requestID == nil {
		t.Fatalf("no requestId in the answer: %s", body)
	}

	var inbound, outbound sdktrace.ReadOnlySpan
	var names []string
	for _, s := range spans.Ended() {
		names = append(names, s.SpanKind().String()+" "+s.Name())
		switch {
		case s.SpanKind() == trace.SpanKindServer:
			inbound = s
		case s.SpanKind() == trace.SpanKindClient && strings.HasSuffix(s.Name(), "KeyPairService/ListKeyPairs"):
			outbound = s
		}
	}
	if inbound == nil || outbound == nil {
		t.Fatalf("want a server span and a ListKeyPairs client span; ended spans: %q", names)
	}
	traceID := inbound.SpanContext().TraceID()
	if outbound.SpanContext().TraceID() != traceID || outbound.Parent().SpanID() != inbound.SpanContext().SpanID() {
		t.Fatalf("client span %s/%s has parent %s, want a child of server span %s/%s",
			outbound.SpanContext().TraceID(), outbound.SpanContext().SpanID(), outbound.Parent().SpanID(),
			traceID, inbound.SpanContext().SpanID())
	}

	md := keys.received()
	want := "00-" + traceID.String() + "-" + outbound.SpanContext().SpanID().String() + "-01"
	if got := md.Get("traceparent"); len(got) != 1 || got[0] != want {
		t.Fatalf("compute received traceparent %v, want %q", got, want)
	}
	if got := md.Get("x-request-id"); len(got) != 1 || got[0] != string(requestID[1]) {
		t.Fatalf("compute received x-request-id %v, want the answer's requestId %q", got, requestID[1])
	}
}

// serveKeys serves keys as the compute KeyPairService on a free loopback
// address until the test ends.
func serveKeys(t *testing.T, keys computev1.KeyPairServiceServer) string {
	t.Helper()
	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	computev1.RegisterKeyPairServiceServer(srv, keys)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

// serveEC2 runs server.Serve with h as the ec2 surface until the test ends
// and returns its address. Another process can take the free address before
// Serve binds it, so a bind failure is retried on a fresh one.
func serveEC2(t *testing.T, h http.Handler) string {
	t.Helper()
	for range 5 {
		lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := lis.Addr().String()
		if err := lis.Close(); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)
		go func() {
			errc <- server.Serve(ctx, server.Options{
				Logger:   slog.New(slog.DiscardHandler),
				Surfaces: []server.Surface{{Name: "ec2", Addr: addr, Handler: h}},
			})
		}()
		err = waitDial(ctx, addr, errc)
		if err == nil {
			t.Cleanup(func() {
				cancel()
				if err := <-errc; err != nil {
					t.Errorf("serve: %v", err)
				}
			})
			return addr
		}
		cancel()
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("serve: %v", err)
		}
	}
	t.Fatal("server.Serve could not bind after 5 attempts")
	return ""
}

// waitDial waits until addr accepts a connection, or returns the error Serve
// stopped with.
func waitDial(ctx context.Context, addr string, errc <-chan error) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case err := <-errc:
			return errors.Join(errors.New("server.Serve stopped before it listened"), err)
		default:
		}
		conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", addr)
		if err == nil {
			return conn.Close()
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// recordingKeys answers ListKeyPairs with no key pairs and keeps the
// metadata of the last call.
type recordingKeys struct {
	computev1.UnimplementedKeyPairServiceServer
	mu sync.Mutex
	md metadata.MD
}

func (k *recordingKeys) ListKeyPairs(
	ctx context.Context, _ *computev1.ListKeyPairsRequest,
) (*computev1.ListKeyPairsResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.md = md.Copy()
	return &computev1.ListKeyPairsResponse{}, nil
}

func (k *recordingKeys) received() metadata.MD {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.md
}
