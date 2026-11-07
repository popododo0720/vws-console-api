package throttle

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func limits(perAccount, global, queue int, wait time.Duration) LaunchLimits {
	return LaunchLimits{PerAccount: perAccount, Global: global, Queue: queue, Wait: wait}
}

type result struct {
	release func()
	err     error
}

// acquireAsync starts an Acquire and returns its result channel once the
// call is queued, so a test orders waiters without sleeping.
func acquireAsync(ctx context.Context, t *testing.T, l *Launches, a resource.AccountID, n int) <-chan result {
	t.Helper()
	_, before, _ := l.held()
	out := make(chan result, 1)
	go func() {
		r, err := l.Acquire(ctx, a, n)
		out <- result{r, err}
	}()
	waitFor(t, "launch queued", func() bool {
		_, waiting, _ := l.held()
		return waiting > before
	})
	return out
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func mustAcquire(t *testing.T, l *Launches, a resource.AccountID, n int) func() {
	t.Helper()
	release, err := l.Acquire(t.Context(), a, n)
	if err != nil {
		t.Fatalf("Acquire(%d): %v", n, err)
	}
	return release
}

func admitted(t *testing.T, ch <-chan result) func() {
	t.Helper()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("waiter: %v", r.err)
		}
		return r.release
	case <-time.After(5 * time.Second):
		t.Fatal("waiter was not admitted")
		return nil
	}
}

func stillWaiting(t *testing.T, ch <-chan result) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("waiter returned early: %v", r.err)
	case <-time.After(20 * time.Millisecond):
	}
}

func isLimit(err error) bool {
	var e *resource.Error
	return errors.As(err, &e) && e.Code == resource.CodeResourceExhausted
}

func idle(t *testing.T, l *Launches) {
	t.Helper()
	waitFor(t, "table back to zero", func() bool {
		inFlight, waiting, accounts := l.held()
		return inFlight == 0 && waiting == 0 && accounts == 0
	})
}

func TestPerAccountCapQueuesTheNextLaunch(t *testing.T) {
	l := NewLaunches(limits(10, 100, 5, 5*time.Second))
	a := account(t, "123456789012")
	hold := mustAcquire(t, l, a, 10)
	next := acquireAsync(t.Context(), t, l, a, 1)
	stillWaiting(t, next)
	hold()
	admitted(t, next)()
	idle(t, l)
}

func TestGlobalCapSpansAccounts(t *testing.T) {
	l := NewLaunches(limits(10, 20, 5, 5*time.Second))
	a, b, c := account(t, "111111111111"), account(t, "222222222222"), account(t, "333333333333")
	holdA := mustAcquire(t, l, a, 10)
	mustAcquire(t, l, b, 10)
	next := acquireAsync(t.Context(), t, l, c, 1)
	stillWaiting(t, next)
	holdA()
	admitted(t, next)()
}

// An account at its cap, with launches queued behind it, does not hold up
// another account's launch.
func TestOneAccountCannotStarveAnother(t *testing.T) {
	l := NewLaunches(limits(10, 20, 50, 5*time.Second))
	a, b := account(t, "111111111111"), account(t, "222222222222")
	holdA := mustAcquire(t, l, a, 10)
	var floods []<-chan result
	for range 20 {
		floods = append(floods, acquireAsync(t.Context(), t, l, a, 10))
	}
	releaseB, err := l.Acquire(t.Context(), b, 10)
	if err != nil {
		t.Fatalf("B behind A's flood: %v", err)
	}
	releaseB()
	holdA()
	admitted(t, floods[0])()
}

// A waiter of B queued behind A's capped launches is admitted when B's own
// room frees, though A's waiters ahead of it still do not fit.
func TestWaiterIsAdmittedPastAnotherAccountsCappedLaunches(t *testing.T) {
	l := NewLaunches(limits(10, 20, 50, 5*time.Second))
	a, b := account(t, "111111111111"), account(t, "222222222222")
	holdA := mustAcquire(t, l, a, 10)
	holdB := mustAcquire(t, l, b, 10)
	blockedA := acquireAsync(t.Context(), t, l, a, 10)
	waitingB := acquireAsync(t.Context(), t, l, b, 10)
	holdB()
	admitted(t, waitingB)()
	stillWaiting(t, blockedA)
	holdA()
	admitted(t, blockedA)()
	idle(t, l)
}

// A launch that would fit waits behind an earlier launch of its own account.
func TestSameAccountKeepsArrivalOrder(t *testing.T) {
	l := NewLaunches(limits(10, 100, 5, 5*time.Second))
	a := account(t, "111111111111")
	hold := mustAcquire(t, l, a, 9)
	big := acquireAsync(t.Context(), t, l, a, 5)
	small := acquireAsync(t.Context(), t, l, a, 1)
	stillWaiting(t, small)
	hold()
	admitted(t, big)()
	admitted(t, small)()
	idle(t, l)
}

func TestQueueBoundRefusesAtOnce(t *testing.T) {
	l := NewLaunches(limits(10, 100, 2, 5*time.Second))
	a := account(t, "111111111111")
	hold := mustAcquire(t, l, a, 10)
	first := acquireAsync(t.Context(), t, l, a, 1)
	second := acquireAsync(t.Context(), t, l, a, 1)
	start := time.Now()
	_, err := l.Acquire(t.Context(), a, 1)
	if !isLimit(err) || time.Since(start) > time.Second {
		t.Fatalf("third waiter: %v after %v, want an immediate resource exhausted", err, time.Since(start))
	}
	hold()
	admitted(t, first)()
	admitted(t, second)()
	idle(t, l)
}

func TestZeroQueueAndZeroWaitRefuse(t *testing.T) {
	for name, lim := range map[string]LaunchLimits{
		"no queue": limits(10, 100, 0, time.Second),
		"no wait":  limits(10, 100, 5, 0),
	} {
		t.Run(name, func(t *testing.T) {
			l := NewLaunches(lim)
			a := account(t, "111111111111")
			hold := mustAcquire(t, l, a, 10)
			if _, err := l.Acquire(t.Context(), a, 1); !isLimit(err) {
				t.Fatalf("over the cap: %v", err)
			}
			hold()
			mustAcquire(t, l, a, 10)()
			idle(t, l)
		})
	}
}

func TestWaitTimeoutRefusesAndLeaksNothing(t *testing.T) {
	l := NewLaunches(limits(10, 100, 5, 30*time.Millisecond))
	a := account(t, "111111111111")
	hold := mustAcquire(t, l, a, 10)
	_, err := l.Acquire(t.Context(), a, 1)
	var e *resource.Error
	want := resource.LaunchLimitExceeded()
	if !errors.As(err, &e) || e.Code != want.Code || e.Message != want.Message {
		t.Fatalf("after the wait: %v", err)
	}
	hold()
	idle(t, l)
	mustAcquire(t, l, a, 10)()
}

func TestCancelReturnsPromptlyAndLeaksNothing(t *testing.T) {
	l := NewLaunches(limits(10, 100, 5, time.Minute))
	a := account(t, "111111111111")
	hold := mustAcquire(t, l, a, 10)
	ctx, cancel := context.WithCancel(t.Context())
	waiting := acquireAsync(ctx, t, l, a, 1)
	cancel()
	select {
	case r := <-waiting:
		if !errors.Is(r.err, context.Canceled) {
			t.Fatalf("cancelled waiter: %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled waiter did not return")
	}
	if _, err := l.Acquire(ctx, a, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire on a cancelled context: %v", err)
	}
	hold()
	idle(t, l)
	mustAcquire(t, l, a, 10)()
}

// Cancel and grant land together: whichever wins, the table ends empty.
func TestCancelRacingAGrantLeaksNothing(t *testing.T) {
	l := NewLaunches(limits(10, 100, 5, time.Minute))
	a := account(t, "111111111111")
	for range 500 {
		hold := mustAcquire(t, l, a, 10)
		ctx, cancel := context.WithCancel(t.Context())
		waiting := acquireAsync(ctx, t, l, a, 10)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); cancel() }()
		go func() { defer wg.Done(); hold() }()
		wg.Wait()
		if r := <-waiting; r.err == nil {
			r.release()
		}
		idle(t, l)
	}
	mustAcquire(t, l, a, 10)()
}

func TestReleaseIsIdempotent(t *testing.T) {
	l := NewLaunches(limits(10, 100, 5, time.Second))
	a := account(t, "111111111111")
	release := mustAcquire(t, l, a, 10)
	other := mustAcquire(t, l, account(t, "222222222222"), 10)
	release()
	release()
	if inFlight, _, _ := l.held(); inFlight != 10 {
		t.Fatalf("in flight after a double release: %d, want 10", inFlight)
	}
	other()
	idle(t, l)
}

func TestNilLaunchesAdmitsEverything(t *testing.T) {
	var l *Launches
	release, err := l.Acquire(t.Context(), account(t, "111111111111"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestOversizedLaunchIsInternal(t *testing.T) {
	l := NewLaunches(limits(10, 100, 5, time.Second))
	for _, n := range []int{0, -1, 11} {
		_, err := l.Acquire(t.Context(), account(t, "111111111111"), n)
		var e *resource.Error
		if !errors.As(err, &e) || e.Code != resource.CodeInternal {
			t.Errorf("Acquire(%d): %v, want internal", n, err)
		}
	}
}

// Many launches across many accounts keep the table within its caps and end
// empty.
func TestConcurrentLaunchesHonorTheCaps(t *testing.T) {
	l := NewLaunches(limits(10, 30, 1000, 10*time.Second))
	accounts := []resource.AccountID{account(t, "111111111111"), account(t, "222222222222"), account(t, "333333333333")}
	var mu sync.Mutex
	perAccount := map[resource.AccountID]int{}
	total := 0
	var wg sync.WaitGroup
	for i := range 300 {
		a := accounts[i%len(accounts)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := l.Acquire(t.Context(), a, 1+i%3)
			if err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			n := 1 + i%3
			mu.Lock()
			perAccount[a] += n
			total += n
			if perAccount[a] > 10 || total > 30 {
				t.Errorf("caps broken: account %d, total %d", perAccount[a], total)
			}
			mu.Unlock()
			time.Sleep(time.Millisecond)
			mu.Lock()
			perAccount[a] -= n
			total -= n
			mu.Unlock()
			release()
		}()
	}
	wg.Wait()
	idle(t, l)
}

func TestLaunchValidateBounds(t *testing.T) {
	if err := DefaultLaunchLimits().Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	for name, lim := range map[string]LaunchLimits{
		"per account under a launch":  limits(9, 100, 5, time.Second),
		"global under a launch":       limits(10, 9, 5, time.Second),
		"per account over global":     limits(50, 40, 5, time.Second),
		"per account too large":       limits(100001, 100001, 5, time.Second),
		"global too large":            limits(10, 100001, 5, time.Second),
		"negative queue":              limits(10, 100, -1, time.Second),
		"queue too large":             limits(10, 100, 100001, time.Second),
		"negative wait":               limits(10, 100, 5, -time.Second),
		"wait past the write timeout": limits(10, 100, 5, 51*time.Second),
	} {
		if lim.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, lim := range map[string]LaunchLimits{
		"smallest": limits(10, 10, 0, 0),
		"largest":  limits(100000, 100000, 100000, 50*time.Second),
	} {
		if err := lim.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
