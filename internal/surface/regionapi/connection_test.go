package regionapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func goodSteps() []resource.ConnectionStep {
	return []resource.ConnectionStep{
		{Name: "tls", Result: resource.ConnectionPass, Message: "PVE TLS certificate verified"},
		{Name: "version", Result: resource.ConnectionPass, Message: "PVE version read succeeded"},
		{Name: "cluster_name", Result: resource.ConnectionFail, Message: "cluster_name differs or could not be verified"},
		{Name: "privileges", Result: resource.ConnectionSkipped, Message: "previous step failed"},
	}
}

func serveConnectionTest(t *testing.T, h http.Handler) (*Client, *http.Client, string) {
	t.Helper()
	cert, clientCert, pool := certificates(t)
	srv := NewServer("", h, cert, pool)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve: %v", err)
		}
	})
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
	anonymous := &http.Client{Transport: &http.Transport{TLSClientConfig: config.Clone()}, Timeout: 2 * time.Second}
	t.Cleanup(anonymous.CloseIdleConnections)
	config.Certificates = []tls.Certificate{clientCert}
	client, err := NewClient("https://"+ln.Addr().String(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client, anonymous, "https://" + ln.Addr().String()
}

func TestConnectionTestRequiresTheGlobalClientCertificate(t *testing.T) {
	var calls atomic.Int32
	h := WithConnectionTest(func(context.Context, json.RawMessage) ([]resource.ConnectionStep, error) {
		calls.Add(1)
		return goodSteps(), nil
	}, http.NotFoundHandler())
	client, anonymous, base := serveConnectionTest(t, h)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+connectionTestPath, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := anonymous.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("a client without a certificate got status %d", resp.StatusCode)
	}
	if calls.Load() != 0 {
		t.Fatal("an unauthenticated request reached the test")
	}
	steps, err := client.TestConnection(t.Context(), json.RawMessage("{}"))
	if err != nil || len(steps) != 4 || calls.Load() != 1 {
		t.Fatalf("authenticated call: %+v %v calls=%d", steps, err, calls.Load())
	}
}

func TestConnectionTestIsServedBeforeTheRegionIsReady(t *testing.T) {
	h := WithConnectionTest(func(context.Context, json.RawMessage) ([]resource.ConnectionStep, error) {
		return goodSteps(), nil
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { WriteNotReady(w, nil) }))
	client, _, _ := serveConnectionTest(t, h)
	if _, err := client.Status(t.Context()); resource.AsError(err).Code != resource.CodeUnavailable {
		t.Fatalf("the region is ready: %v", err)
	}
	if _, err := client.TestConnection(t.Context(), json.RawMessage("{}")); err != nil {
		t.Fatalf("the test needs a ready region: %v", err)
	}
}

func TestConnectionTestBoundsAndSanitizes(t *testing.T) {
	const canary = "token-canary-9431"
	var failure error
	var called atomic.Int32
	h := WithConnectionTest(func(_ context.Context, data json.RawMessage) ([]resource.ConnectionStep, error) {
		called.Add(1)
		if len(data) > 100 {
			t.Error("an oversized body reached the test")
		}
		return nil, failure
	}, http.NotFoundHandler())
	client, _, _ := serveConnectionTest(t, h)
	big := bytes.Repeat([]byte("x"), (64<<10)+1)
	if _, err := client.TestConnection(t.Context(), big); err == nil || called.Load() != 0 {
		t.Fatalf("oversized body: %v called=%d", err, called.Load())
	}
	failure = errors.New("upstream said " + canary)
	_, err := client.TestConnection(t.Context(), json.RawMessage("{}"))
	if e := resource.AsError(err); e.Code != resource.CodeUnavailable || e.Message != "connection test failed" ||
		strings.Contains(err.Error(), canary) {
		t.Fatalf("an internal failure was not sanitized: %v", err)
	}
	failure = resource.Invalid("caPem", "expected the PEM certificates that sign the PVE nodes")
	_, err = client.TestConnection(t.Context(), json.RawMessage("{}"))
	if e := resource.AsError(err); e.Code != resource.CodeInvalidArgument || e.Field != "caPem" {
		t.Fatalf("a validation failure was lost: %v", err)
	}
}

func TestConnectionTestRunsAtMostTwoAtOnce(t *testing.T) {
	release := make(chan struct{})
	var running atomic.Int32
	entered := make(chan struct{}, 4)
	h := WithConnectionTest(func(context.Context, json.RawMessage) ([]resource.ConnectionStep, error) {
		running.Add(1)
		entered <- struct{}{}
		<-release
		running.Add(-1)
		return goodSteps(), nil
	}, http.NotFoundHandler())
	client, _, _ := serveConnectionTest(t, h)
	var wg sync.WaitGroup
	for range maxConnectionTests {
		wg.Go(func() {
			if _, err := client.TestConnection(t.Context(), json.RawMessage("{}")); err != nil {
				t.Error(err)
			}
		})
	}
	for range maxConnectionTests {
		<-entered
	}
	_, err := client.TestConnection(t.Context(), json.RawMessage("{}"))
	if e := resource.AsError(err); e.Code != resource.CodeUnavailable || e.Message != "connection test busy" {
		t.Fatalf("a third concurrent test: %v", err)
	}
	if running.Load() != maxConnectionTests {
		t.Fatalf("running = %d", running.Load())
	}
	close(release)
	wg.Wait()
	if _, err := client.TestConnection(t.Context(), json.RawMessage("{}")); err != nil {
		t.Fatalf("the slot was not released: %v", err)
	}
}

func TestConnectionTestIsBoundedByItsDeadline(t *testing.T) {
	var deadline time.Time
	h := WithConnectionTest(func(ctx context.Context, _ json.RawMessage) ([]resource.ConnectionStep, error) {
		deadline, _ = ctx.Deadline()
		return goodSteps(), nil
	}, http.NotFoundHandler())
	client, _, _ := serveConnectionTest(t, h)
	start := time.Now()
	if _, err := client.TestConnection(t.Context(), json.RawMessage("{}")); err != nil {
		t.Fatal(err)
	}
	if deadline.IsZero() || deadline.Sub(start) > connectionTestLimit+time.Second {
		t.Fatalf("the test has no deadline within %v: %v", connectionTestLimit, deadline)
	}
}

func TestClientRefusesAnUnexpectedConnectionResult(t *testing.T) {
	const canary = "upstream-body-canary"
	bad := map[string][]resource.ConnectionStep{
		"upstream text": {
			{Name: "tls", Result: resource.ConnectionFail, Message: canary},
			{Name: "version", Result: resource.ConnectionSkipped, Message: "previous step failed"},
			{Name: "cluster_name", Result: resource.ConnectionSkipped, Message: "previous step failed"},
			{Name: "privileges", Result: resource.ConnectionSkipped, Message: "previous step failed"},
		},
		"missing step": goodSteps()[:3],
		"renamed step": append([]resource.ConnectionStep{
			{Name: "dns", Result: resource.ConnectionPass, Message: "x"},
		}, goodSteps()[1:]...),
		"pass after failure": {
			{Name: "tls", Result: resource.ConnectionFail, Message: "PVE TLS handshake failed"},
			{Name: "version", Result: resource.ConnectionPass, Message: "PVE version read succeeded"},
			{Name: "cluster_name", Result: resource.ConnectionSkipped, Message: "previous step failed"},
			{Name: "privileges", Result: resource.ConnectionSkipped, Message: "previous step failed"},
		},
		"no steps": nil,
	}
	for name, steps := range bad {
		t.Run(name, func(t *testing.T) {
			h := WithConnectionTest(func(context.Context, json.RawMessage) ([]resource.ConnectionStep, error) {
				return steps, nil
			}, http.NotFoundHandler())
			client, _, _ := serveConnectionTest(t, h)
			got, err := client.TestConnection(t.Context(), json.RawMessage("{}"))
			if err == nil || got != nil || strings.Contains(err.Error(), canary) {
				t.Fatalf("accepted %+v: %v", got, err)
			}
		})
	}
}

func TestConnectionTestAcceptsOnlyPost(t *testing.T) {
	rec := httptest.NewRecorder()
	h := WithConnectionTest(func(context.Context, json.RawMessage) ([]resource.ConnectionStep, error) {
		return goodSteps(), nil
	}, http.NotFoundHandler())
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, connectionTestPath, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET status = %d, want the next handler's 404", rec.Code)
	}
}

func TestConnectionTestBudgetCoversTheBodyRead(t *testing.T) {
	h := WithConnectionTest(func(context.Context, json.RawMessage) ([]resource.ConnectionStep, error) {
		return goodSteps(), nil
	}, http.NotFoundHandler())
	client, _, base := serveConnectionTest(t, h)
	// Each stalled upload sends part of its body and never the rest.
	var writers []*io.PipeWriter
	for range maxConnectionTests {
		body, writer := io.Pipe()
		writers = append(writers, writer)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+connectionTestPath, body)
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = 100
		go func() {
			if resp, err := client.http.Do(req); err == nil {
				_ = resp.Body.Close()
			}
		}()
		if _, err := writer.Write([]byte("{")); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, w := range writers {
			_ = w.Close()
		}
	})
	_, err := client.TestConnection(t.Context(), json.RawMessage("{}"))
	if resource.AsError(err).Code != resource.CodeUnavailable {
		t.Fatalf("stalled uploads hold no slot: %v", err)
	}
	// The server's read timeout is 60 s; the budget must free both slots well before it.
	start := time.Now()
	for {
		_, err := client.TestConnection(t.Context(), json.RawMessage("{}"))
		if err == nil {
			break
		}
		if time.Since(start) > connectionTestLimit+5*time.Second {
			t.Fatalf("a stalled upload held its slot past the %v budget: %v", connectionTestLimit, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
