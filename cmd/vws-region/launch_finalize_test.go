package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/popododo0720/vws-lib/obs/report"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestLaunchFinalizerUnsupportedStopsWithoutReporting(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		wantCalls   int
		wantReports int
	}{
		{"read-only", resource.Unsupported("FinalizeLaunches", "read-only"), 1, 0},
		{"wrapped", fmt.Errorf("backend: %w", resource.Unsupported("FinalizeLaunches", "read-only")), 1, 0},
		{"other-error", errors.New("inventory unavailable"), 2, 2},
		{"invalid-argument", resource.Invalid("FinalizeLaunches", "invalid inventory"), 2, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reported []error
			report.Configure(report.Sink{Capture: func(_ context.Context, err error, _ map[string]string) {
				reported = append(reported, err)
			}})
			t.Cleanup(func() { report.Configure(report.Sink{}) })
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ticks := make(chan time.Time, 3)
			for range cap(ticks) {
				ticks <- time.Time{}
			}
			admissions, calls := 0, 0
			finalizeLaunches(ctx, func(context.Context) (string, error) {
				admissions++
				if admissions == 3 {
					cancel()
					return "", context.Canceled
				}
				return "", nil
			}, func(context.Context, func(context.Context) error) error {
				calls++
				return tc.err
			}, ticks)
			if calls != tc.wantCalls || len(reported) != tc.wantReports {
				t.Fatalf("finalize calls=%d reports=%d, want calls=%d reports=%d",
					calls, len(reported), tc.wantCalls, tc.wantReports)
			}
			for _, err := range reported {
				if !errors.Is(err, tc.err) || err.Error() != "finalize launches: "+tc.err.Error() {
					t.Errorf("reported error=%v, want wrapped %v", err, tc.err)
				}
			}
		})
	}
}

func TestLaunchFinalizerLeaderGate(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ticks := make(chan time.Time)
	checked := make(chan struct{})
	done := make(chan struct{})
	calls := 0
	go func() {
		defer close(done)
		finalizeLaunches(ctx, func(context.Context) (string, error) {
			calls++
			checked <- struct{}{}
			switch calls {
			case 1:
				return "", errors.New("fenced")
			case 2:
				return "peer", nil
			default:
				return "", nil
			}
		}, func(context.Context, func(context.Context) error) error {
			if calls < 3 {
				t.Error("finalized without local leadership")
			}
			if calls == 3 {
				return errors.New("retry on next tick")
			}
			cancel()
			return nil
		}, ticks)
	}()
	for range 4 {
		select {
		case ticks <- time.Time{}:
			<-checked
		case <-ctx.Done():
			t.Fatal("finalizer stopped early")
		}
	}
	<-done
	if calls != 4 {
		t.Fatalf("admissions=%d", calls)
	}
}
