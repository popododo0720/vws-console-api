package main

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TestServeServesObsHealth proves VWS_HEALTH_ADDR opens the shared /healthz
// and /readyz listener. serve is the only caller of obs.Setup, so the health
// handler's process-wide readiness is not spent by another test.
func TestServeServesObsHealth(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	healthAddr := freeAddr(t)
	t.Setenv("VWS_HEALTH_ADDR", healthAddr)

	args := []string{
		"-backend=fake",
		"-console-addr=" + freeAddr(t),
		"-ec2-addr=" + freeAddr(t),
		"-s3-addr=" + freeAddr(t),
		"-iam-addr=" + freeAddr(t),
		"-ops-addr=",
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, args) }()
	t.Cleanup(cancel)
	waitListen(t, healthAddr)
	for _, path := range []string{"/healthz", "/readyz"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+healthAddr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %d", path, resp.StatusCode)
		}
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(smokeTimeout):
		t.Fatal("serve did not stop")
	}
}
