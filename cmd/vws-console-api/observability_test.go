package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// obsHealthChild marks the test process that runs the body of
// TestServeServesObsHealth.
const obsHealthChild = "VWS_TEST_OBS_HEALTH_CHILD"

// TestServeServesObsHealth proves VWS_HEALTH_ADDR opens the shared /healthz
// and /readyz listener. serve is the only caller of obs.Setup, so the health
// handler's process-wide readiness is not spent by another test.
//
// That readiness is health.Default, and shutdown marks it not ready for the
// life of the process. A second run in one process, as under -count=20, got
// /readyz 503 (issue #486). Each run therefore starts a fresh test process.
func TestServeServesObsHealth(t *testing.T) {
	if os.Getenv(obsHealthChild) == "" {
		cmd := exec.CommandContext(t.Context(), os.Args[0],
			"-test.run=^TestServeServesObsHealth$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), obsHealthChild+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "--- PASS: TestServeServesObsHealth") {
			t.Fatalf("child test process: %v\n%s", err, out)
		}
		return
	}

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
	client := &http.Client{Transport: &http.Transport{}}
	for _, path := range []string{"/healthz", "/readyz"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+healthAddr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %d", path, resp.StatusCode)
		}
	}

	// The client can leave an idle connection it opened but never used.
	// http.Server.Shutdown leaves a connection in StateNew alone until it is
	// five seconds old (golang/go#22682), so the five second drain deadline
	// expired first and serve returned context.DeadlineExceeded (issue #486,
	// as #416). Close the client's idle connections first; any error after
	// that is real.
	client.CloseIdleConnections()
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
