package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadinessBoundsPVEChecks(t *testing.T) {
	var checks atomic.Int32
	down := errors.New("pve down")
	var fail atomic.Bool
	now := time.Unix(0, 0)
	r := &readiness{check: func(context.Context) error {
		checks.Add(1)
		if fail.Load() {
			return down
		}
		return nil
	}, now: func() time.Time { return now }, ttl: readyTTL}
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if err := r.Ready(t.Context()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if got := checks.Load(); got != 1 {
		t.Fatalf("50 concurrent probes ran %d PVE checks, want 1", got)
	}
	fail.Store(true)
	now = now.Add(readyTTL - time.Nanosecond)
	if err := r.Ready(t.Context()); err != nil || checks.Load() != 1 {
		t.Fatalf("probe inside the TTL: err %v, checks %d", err, checks.Load())
	}
	now = now.Add(time.Nanosecond)
	if err := r.Ready(t.Context()); !errors.Is(err, down) || checks.Load() != 2 {
		t.Fatalf("probe after the TTL: err %v, checks %d", err, checks.Load())
	}
	fail.Store(false)
	now = now.Add(readyTTL)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_ = r.Ready(ctx)
	if err := r.Ready(t.Context()); err != nil || checks.Load() != 4 {
		t.Fatalf("a cancelled probe was cached: err %v, checks %d", err, checks.Load())
	}
}

func TestTokenInputsAreRefused(t *testing.T) {
	const secret = "must-never-be-echoed"
	for _, args := range [][]string{
		{"-token=" + secret},
		{"-pve-token=" + secret},
		{"-secret=" + secret},
		{"-backend=fake"},
		{"unexpected"},
		{"-ec2-addr=:8081"},
		{"-s3-addr=:8082"},
		{"-console-addr=:8080"},
		{"-pve-endpoint=https://user:" + secret + "@localhost:8006"},
	} {
		if err := run(t.Context(), args); err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("input not safely refused: %v", err)
		}
	}
	for _, name := range []string{"PVE_TOKEN", "PROXMOX_API_TOKEN", "VWS_PVE_TOKEN", "VWS_PVE_TOKEN_FILE"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, secret)
			if err := run(t.Context(), nil); err == nil || !strings.Contains(err.Error(), "environment") ||
				strings.Contains(err.Error(), secret) {
				t.Fatalf("environment not safely refused: %v", err)
			}
		})
	}
}

func TestHelperRootRequiresExplicitPath(t *testing.T) {
	for _, args := range [][]string{
		{"-helper-root", "/fixture"},
		{"-helper-root", ""},
		{"-helper-root", "relative", "-helper-path", "/helper"},
		{"-helper-root", "/fixture/../escape", "-helper-path", "/helper"},
	} {
		if err := run(t.Context(), args); err == nil ||
			!strings.Contains(err.Error(), "helper-root requires") {
			t.Fatalf("invalid helper-root flags %q: %v", args, err)
		}
	}
}
