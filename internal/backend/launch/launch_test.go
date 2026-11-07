package launch_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
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
	plan := func(attempt int) []launch.Step {
		return []launch.Step{{Kind: launch.StepVolume, Resource: "v" + strconv.Itoa(attempt)}}
	}
	l, err := tr.Begin(ctx, "k", account(t), "fp", 1, plan)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := l.Done(ctx, plan(1)[0]); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if undo, err := l.Undo(ctx); err != nil || !undo {
			t.Fatalf("undo %v err %v", undo, err)
		}
	}
	for range 2 {
		if err := l.Undone(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := store.Writes(); got != 4 {
		t.Fatalf("writes %d want 4: create, step, undoing, failed", got)
	}
	again, err := tr.Begin(ctx, "k", account(t), "fp", 1, plan)
	if err != nil {
		t.Fatal(err)
	}
	rec := again.Record()
	if rec.Phase != launch.Running || rec.Attempt != 2 || len(rec.Steps) != 0 || !slices.Equal(rec.Plan, plan(2)) {
		t.Fatalf("retried record %+v", rec)
	}
	for range 2 {
		if err := again.Succeed(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if undo, err := again.Undo(ctx); err != nil || undo {
		t.Fatalf("undo of a success: %v err %v", undo, err)
	}
	if _, err := tr.Begin(ctx, "k", account(t), "fp", 1, plan); err != nil {
		t.Fatal(err)
	}
	rec, _, _, err = store.Load(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Phase != launch.Succeeded || store.Writes() != 6 {
		t.Fatalf("phase %s writes %d: succeeded is final", rec.Phase, store.Writes())
	}
}

// TestSuccessAfterAnUndoIsRefused pins that a request whose attempt another
// request of the same token began to undo cannot record a step or report
// success, and is told to undo again, so a create it made late is deleted.
func TestSuccessAfterAnUndoIsRefused(t *testing.T) {
	ctx := context.Background()
	store := &launch.Memory{}
	tr := launch.NewTracker(store, fixed)
	failing, err := tr.Begin(ctx, "k", account(t), "fp", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	slow, err := tr.Begin(ctx, "k", account(t), "fp", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if undo, err := failing.Undo(ctx); err != nil || !undo {
		t.Fatalf("undo %v err %v", undo, err)
	}
	err = slow.Succeed(ctx)
	if resource.CodeOf(err) != resource.CodeUnavailable || !errors.Is(err, launch.ErrUndone) {
		t.Fatalf("success during an undo: %v", err)
	}
	if undo, err := slow.Undo(ctx); err != nil || !undo {
		t.Fatalf("a second request of the attempt resumes the undo: %v err %v", undo, err)
	}
	if err := slow.Done(ctx, launch.Step{Kind: launch.StepVolume, Resource: "late"}); !errors.Is(err, launch.ErrUndone) {
		t.Fatalf("step during an undo: %v", err)
	}
	if err := failing.Undone(ctx); err != nil {
		t.Fatal(err)
	}
	if undo, err := slow.Undo(ctx); err != nil || !undo {
		t.Fatalf("a request whose create landed after the undo deletes it: %v err %v", undo, err)
	}
	if rec := failing.Record(); rec.Phase != launch.Failed || len(rec.Steps) != 0 || store.Writes() != 3 {
		t.Fatalf("record %+v writes %d", rec, store.Writes())
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

// TestStaleAttemptCannotFailARetry pins that a request a retry replaced
// cannot undo, record a step in or succeed the retry's attempt.
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
	if _, err := first.Undo(ctx); err != nil {
		t.Fatal(err)
	}
	if err := first.Undone(ctx); err != nil {
		t.Fatal(err)
	}
	retry, err := tr.Begin(ctx, "k", account(t), "fp", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Record().Attempt != 2 || retry.Record().Phase != launch.Running {
		t.Fatalf("retry record %+v", retry.Record())
	}
	writes := store.Writes()
	if undo, err := slow.Undo(ctx); err != nil || undo {
		t.Fatalf("stale undo %v err %v", undo, err)
	}
	if err := slow.Undone(ctx); err != nil {
		t.Fatal(err)
	}
	if err := slow.Done(ctx, launch.Step{Kind: launch.StepVolume, Resource: "v"}); !errors.Is(err, launch.ErrUndone) {
		t.Fatalf("stale step: %v", err)
	}
	if err := slow.Succeed(ctx); !errors.Is(err, launch.ErrUndone) {
		t.Fatalf("stale success: %v", err)
	}
	rec, _, _, err := store.Load(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Phase != launch.Running || rec.Attempt != 2 || len(rec.Steps) != 0 || store.Writes() != writes {
		t.Fatalf("record %+v writes %d: the stale attempt changed the retry", rec, store.Writes()-writes)
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
	if err := l.Succeed(ctx); err != nil {
		t.Fatal(err)
	}
	if rec := l.Record(); rec.Phase != launch.Succeeded || len(rec.Steps) != 1 || store.Writes() != 3 {
		t.Fatalf("record %+v writes %d", rec, store.Writes())
	}
}

// TestAbandonedIsAnIdleRunningOrUndoingLaunch pins that the sweep sees a
// launch left running or undoing for the idle time, as its latest attempt,
// and never a launch written since, one that succeeded or one already failed.
func TestAbandonedIsAnIdleRunningOrUndoingLaunch(t *testing.T) {
	ctx := context.Background()
	store := &launch.Memory{}
	idle := 10 * time.Minute
	old := launch.NewTracker(store, func() time.Time { return fixed().Add(-idle) })
	fresh := launch.NewTracker(store, fixed)
	begin := func(tr *launch.Tracker, key string) launch.Launch {
		t.Helper()
		l, err := tr.Begin(ctx, key, account(t), "fp", 1, nil)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	begin(old, "running")
	begin(fresh, "live")
	undoing := begin(old, "undoing")
	if _, err := undoing.Undo(ctx); err != nil {
		t.Fatal(err)
	}
	failed := begin(old, "failed")
	if _, err := failed.Undo(ctx); err != nil {
		t.Fatal(err)
	}
	if err := failed.Undone(ctx); err != nil {
		t.Fatal(err)
	}
	retried := begin(old, "failed")
	if retried.Attempt() != 2 {
		t.Fatalf("retry attempt %d want 2", retried.Attempt())
	}
	succeeded := begin(old, "succeeded")
	if err := succeeded.Succeed(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := fresh.Abandoned(ctx, idle)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]int{}
	for _, l := range got {
		keys[l.Record().Key] = l.Attempt()
	}
	want := map[string]int{"running": 1, "undoing": 1, "failed": 2}
	if len(keys) != len(want) {
		t.Fatalf("abandoned %v want %v", keys, want)
	}
	for k, attempt := range want {
		if keys[k] != attempt {
			t.Fatalf("abandoned %v want %v", keys, want)
		}
	}
	if got, err := old.Abandoned(ctx, idle); err != nil || len(got) != 0 {
		t.Fatalf("abandoned before the idle time %d err %v", len(got), err)
	}
}

// TestAbandonedLaunchIsUndoneOnce pins that undoing an abandoned launch
// writes undoing and failed once, and a request of that attempt can no
// longer record a step or succeed.
func TestAbandonedLaunchIsUndoneOnce(t *testing.T) {
	ctx := context.Background()
	store := &launch.Memory{}
	plan := func(int) []launch.Step { return []launch.Step{{Kind: launch.StepVolume, Resource: "v"}} }
	live, err := launch.NewTracker(store, fixed).Begin(ctx, "k", account(t), "fp", 1, plan)
	if err != nil {
		t.Fatal(err)
	}
	later := launch.NewTracker(store, func() time.Time { return fixed().Add(time.Hour) })
	got, err := later.Abandoned(ctx, time.Minute)
	if err != nil || len(got) != 1 {
		t.Fatalf("abandoned %d err %v", len(got), err)
	}
	writes := store.Writes()
	if undo, err := got[0].Undo(ctx); err != nil || !undo {
		t.Fatalf("undo %v err %v", undo, err)
	}
	if err := got[0].Undone(ctx); err != nil {
		t.Fatal(err)
	}
	if n := store.Writes() - writes; n != 2 {
		t.Fatalf("writes %d want 2: undoing, failed", n)
	}
	if err := live.Done(ctx, plan(1)[0]); !errors.Is(err, launch.ErrUndone) {
		t.Fatalf("step after the sweep: %v", err)
	}
	if err := live.Succeed(ctx); !errors.Is(err, launch.ErrUndone) {
		t.Fatalf("success after the sweep: %v", err)
	}
}

// TestAbandonedLaunchWrittenSinceIsLeftAlone pins that the sweep does not
// claim a launch a retry wrote after the listing: its Undo reports false and
// writes nothing, and the retry goes on.
func TestAbandonedLaunchWrittenSinceIsLeftAlone(t *testing.T) {
	ctx := context.Background()
	store := &launch.Memory{}
	plan := func(int) []launch.Step {
		return []launch.Step{{Kind: launch.StepVolume, Resource: "v"}, {Kind: launch.StepInstance, Resource: "i"}}
	}
	now := fixed()
	clock := func() time.Time { return now }
	if _, err := launch.NewTracker(store, clock).Begin(ctx, "k", account(t), "fp", 1, plan); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	tr := launch.NewTracker(store, clock)
	got, err := tr.Abandoned(ctx, time.Minute)
	if err != nil || len(got) != 1 {
		t.Fatalf("abandoned %d err %v", len(got), err)
	}
	retry, err := tr.Begin(ctx, "k", account(t), "fp", 1, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := retry.Done(ctx, plan(1)[0]); err != nil {
		t.Fatal(err)
	}
	writes := store.Writes()
	if undo, err := got[0].Undo(ctx); err != nil || undo {
		t.Fatalf("undo of a launch written since: %v err %v", undo, err)
	}
	if store.Writes() != writes {
		t.Fatal("the refused undo wrote the record")
	}
	if err := retry.Done(ctx, plan(1)[1]); err != nil {
		t.Fatal(err)
	}
	if err := retry.Succeed(ctx); err != nil {
		t.Fatal(err)
	}
}
