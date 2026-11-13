package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

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
		}, func(context.Context) error {
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
