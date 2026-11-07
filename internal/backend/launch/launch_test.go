package launch_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/launch"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func account(t *testing.T) resource.AccountID {
	t.Helper()
	a, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func fixed() time.Time { return time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC) }

func TestPhaseTransitionsWriteOnce(t *testing.T) {
	ctx := context.Background()
	store := &launch.Memory{}
	tr := launch.NewTracker(store, fixed)
	l, err := tr.Begin(ctx, "k", account(t), "fp", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	step := launch.Step{Kind: launch.StepVolume, Index: 0, Resource: "v"}
	for range 2 {
		if err := l.Done(ctx, step); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Finish(ctx, launch.Failed); err != nil {
		t.Fatal(err)
	}
	if err := l.Finish(ctx, launch.Failed); err != nil {
		t.Fatal(err)
	}
	if got := store.Writes(); got != 3 {
		t.Fatalf("writes %d want 3: create, step, failed", got)
	}
	again, err := tr.Begin(ctx, "k", account(t), "fp", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again.Record().Phase != launch.Running || len(again.Record().Steps) != 1 {
		t.Fatalf("retried record %+v", again.Record())
	}
	if err := again.Finish(ctx, launch.Succeeded); err != nil {
		t.Fatal(err)
	}
	if err := again.Finish(ctx, launch.Failed); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Begin(ctx, "k", account(t), "fp", 1, nil); err != nil {
		t.Fatal(err)
	}
	rec, _, _, err := store.Load(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Phase != launch.Succeeded || store.Writes() != 5 {
		t.Fatalf("phase %s writes %d: succeeded is final", rec.Phase, store.Writes())
	}
}

func TestStoreFailureIsUnavailable(t *testing.T) {
	ctx := context.Background()
	store := &launch.Memory{}
	cause := errors.New("down")
	store.FailAfter(0, cause)
	tr := launch.NewTracker(store, fixed)
	_, err := tr.Begin(ctx, "k", account(t), "fp", 1, nil)
	if resource.CodeOf(err) != resource.CodeUnavailable || !errors.Is(err, cause) {
		t.Fatalf("err %v", err)
	}
	l, err := tr.Begin(ctx, "k", account(t), "fp", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	store.FailAfter(0, cause)
	err = l.Done(ctx, launch.Step{Kind: launch.StepVolume, Resource: "v"})
	if resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("done err %v", err)
	}
}

// TestStaleAttemptCannotFailARetry pins that a request a retry replaced cannot
// mark the retry's launch failed.
func TestStaleAttemptCannotFailARetry(t *testing.T) {
	ctx := context.Background()
	store := &launch.Memory{}
	tr := launch.NewTracker(store, fixed)
	first, err := tr.Begin(ctx, "k", account(t), "fp", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	slow, err := tr.Begin(ctx, "k", account(t), "fp", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Finish(ctx, launch.Failed); err != nil {
		t.Fatal(err)
	}
	retry, err := tr.Begin(ctx, "k", account(t), "fp", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Record().Attempt != 2 || retry.Record().Phase != launch.Running {
		t.Fatalf("retry record %+v", retry.Record())
	}
	if err := slow.Finish(ctx, launch.Failed); err != nil {
		t.Fatal(err)
	}
	rec, _, _, err := store.Load(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Phase != launch.Running || rec.Attempt != 2 {
		t.Fatalf("record %+v: the stale attempt failed the retry", rec)
	}
}

// TestRacingRequestsLandEveryStep runs requests with one token at once: every
// step lands and each step is one write.
func TestRacingRequestsLandEveryStep(t *testing.T) {
	ctx := context.Background()
	store := &launch.Memory{}
	tr := launch.NewTracker(store, fixed)
	const n = 8
	errs := make(chan error, n)
	for i := range n {
		go func() {
			l, err := tr.Begin(ctx, "k", account(t), "fp", n, nil)
			if err == nil {
				err = l.Done(ctx, launch.Step{Kind: launch.StepVolume, Index: i, Resource: "v"})
			}
			errs <- err
		}()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	rec, _, _, err := store.Load(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Steps) != n || store.Writes() != n+1 {
		t.Fatalf("steps %d writes %d want %d and %d", len(rec.Steps), store.Writes(), n, n+1)
	}
}

// TestWritesOutliveACancelledRequest pins that a completed create and the
// launch's end are recorded after the client hangs up.
func TestWritesOutliveACancelledRequest(t *testing.T) {
	store := &launch.Memory{}
	l, err := launch.NewTracker(store, fixed).Begin(context.Background(), "k", account(t), "fp", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Done(ctx, launch.Step{Kind: launch.StepVolume, Resource: "v"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Finish(ctx, launch.Succeeded); err != nil {
		t.Fatal(err)
	}
	if rec := l.Record(); rec.Phase != launch.Succeeded || len(rec.Steps) != 1 || store.Writes() != 3 {
		t.Fatalf("record %+v writes %d", rec, store.Writes())
	}
}
