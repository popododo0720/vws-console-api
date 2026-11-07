package throttle

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// LaunchLimits sizes the RunInstances admission table. The caps count
// instances, not requests, because a launch of ten instances costs the
// backend ten times a launch of one.
type LaunchLimits struct {
	// PerAccount is the instances one account may have in flight.
	PerAccount int
	// Global is the instances in flight across all accounts.
	Global int
	// Queue is the launches that may wait at once, all accounts together.
	Queue int
	// Wait is the longest a launch waits for room.
	Wait time.Duration
}

// Bounds a LaunchLimits field must stay within. minLaunchCap is the most
// instances one RunInstances may ask for, so any launch fits an empty table.
const (
	minLaunchCap = 10
	maxLaunchCap = 100000
	maxQueue     = 100000
	// maxWait stays under the 60 s HTTP write timeout, so a queued launch is
	// answered before the listener gives up on the connection.
	maxWait = 50 * time.Second
)

// DefaultLaunchLimits returns 20 instances in flight per account, 100 in all,
// 200 waiting launches and a 10 s wait.
func DefaultLaunchLimits() LaunchLimits {
	return LaunchLimits{PerAccount: 20, Global: 100, Queue: 200, Wait: 10 * time.Second}
}

// Validate reports the first field outside its bounds: PerAccount and Global
// 10 to 100000 with PerAccount at most Global, Queue 0 to 100000, Wait 0 to
// 50s.
func (l LaunchLimits) Validate() error {
	if l.PerAccount < minLaunchCap || l.PerAccount > maxLaunchCap {
		return fmt.Errorf("per-account in flight %d: want %d to %d", l.PerAccount, minLaunchCap, maxLaunchCap)
	}
	if l.Global < minLaunchCap || l.Global > maxLaunchCap {
		return fmt.Errorf("global in flight %d: want %d to %d", l.Global, minLaunchCap, maxLaunchCap)
	}
	if l.PerAccount > l.Global {
		return fmt.Errorf("per-account in flight %d exceeds global %d", l.PerAccount, l.Global)
	}
	if l.Queue < 0 || l.Queue > maxQueue {
		return fmt.Errorf("queue %d: want 0 to %d", l.Queue, maxQueue)
	}
	if l.Wait < 0 || l.Wait > maxWait {
		return fmt.Errorf("queue wait %v: want 0 to %v", l.Wait, maxWait)
	}
	return nil
}

type waiter struct {
	account resource.AccountID
	n       int
	granted bool
	ready   chan struct{}
}

// Launches admits RunInstances calls against LaunchLimits. A launch that does
// not fit waits in a bounded FIFO queue. When room frees, every waiter that
// fits is admitted in order and one that does not is skipped, so an account at
// its own cap never holds up another account's launch. Within one account
// launches stay in arrival order. State is per process.
type Launches struct {
	limits LaunchLimits

	mu        sync.Mutex
	inFlight  int
	byAccount map[resource.AccountID]int
	queued    map[resource.AccountID]int
	queue     []*waiter
}

// NewLaunches returns a table. limits must pass Validate.
func NewLaunches(limits LaunchLimits) *Launches {
	return &Launches{
		limits:    limits,
		byAccount: map[resource.AccountID]int{},
		queued:    map[resource.AccountID]int{},
	}
}

// Acquire admits n instances for account, waiting in the queue up to Wait or
// until ctx ends. The release func returns the room and is safe to call more
// than once. Past the queue or the wait it returns LaunchLimitExceeded. A nil
// Launches admits everything.
func (l *Launches) Acquire(ctx context.Context, account resource.AccountID, n int) (func(), error) {
	if l == nil {
		return func() {}, nil
	}
	if n < 1 || n > l.limits.PerAccount {
		return nil, resource.Internal(fmt.Errorf("launch of %d instances against a cap of %d", n, l.limits.PerAccount))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.queued[account] == 0 && l.fits(account, n) {
		l.take(account, n)
		l.mu.Unlock()
		return l.releaser(account, n), nil
	}
	if l.limits.Wait <= 0 || len(l.queue) >= l.limits.Queue {
		l.mu.Unlock()
		return nil, resource.LaunchLimitExceeded()
	}
	w := &waiter{account: account, n: n, ready: make(chan struct{})}
	l.queue = append(l.queue, w)
	l.queued[account]++
	l.mu.Unlock()

	timer := time.NewTimer(l.limits.Wait)
	defer timer.Stop()
	var cause error
	select {
	case <-w.ready:
		return l.releaser(account, n), nil
	case <-ctx.Done():
		cause = ctx.Err()
	case <-timer.C:
		cause = resource.LaunchLimitExceeded()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if w.granted {
		l.give(account, n)
		l.dispatch()
		return nil, cause
	}
	l.remove(w)
	l.dispatch()
	return nil, cause
}

func (l *Launches) fits(account resource.AccountID, n int) bool {
	return l.byAccount[account]+n <= l.limits.PerAccount && l.inFlight+n <= l.limits.Global
}

func (l *Launches) take(account resource.AccountID, n int) {
	l.inFlight += n
	l.byAccount[account] += n
}

func (l *Launches) give(account resource.AccountID, n int) {
	l.inFlight -= n
	if l.byAccount[account] -= n; l.byAccount[account] <= 0 {
		delete(l.byAccount, account)
	}
}

func (l *Launches) releaser(account resource.AccountID, n int) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.give(account, n)
			l.dispatch()
		})
	}
}

// remove drops a waiter that gave up. The caller holds mu.
func (l *Launches) remove(w *waiter) {
	for i, q := range l.queue {
		if q == w {
			l.queue = append(l.queue[:i], l.queue[i+1:]...)
			l.unqueue(w.account)
			return
		}
	}
}

func (l *Launches) unqueue(account resource.AccountID) {
	if l.queued[account]--; l.queued[account] <= 0 {
		delete(l.queued, account)
	}
}

// dispatch admits every waiter that fits, in queue order. Once an account has
// a waiter that does not fit, its later waiters stay behind it. The caller
// holds mu.
func (l *Launches) dispatch() {
	var blocked map[resource.AccountID]bool
	kept := l.queue[:0]
	for i, w := range l.queue {
		if l.inFlight >= l.limits.Global {
			kept = append(kept, l.queue[i:]...)
			break
		}
		if !blocked[w.account] && l.fits(w.account, w.n) {
			l.take(w.account, w.n)
			l.unqueue(w.account)
			w.granted = true
			close(w.ready)
			continue
		}
		if blocked == nil {
			blocked = map[resource.AccountID]bool{}
		}
		blocked[w.account] = true
		kept = append(kept, w)
	}
	clear(l.queue[len(kept):])
	l.queue = kept
}

// held is the instances in flight, the waiting launches and the accounts
// tracked (tests).
func (l *Launches) held() (inFlight, waiting, accounts int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inFlight, len(l.queue), len(l.byAccount) + len(l.queued)
}
