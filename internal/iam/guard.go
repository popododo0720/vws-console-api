package iam

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Sign-in abuse limits.
const (
	// MaxLoginFailures failed sign-ins in a row, from one address for one
	// user, lock that user from that address only. Nobody can lock a user
	// (or root) out from somewhere else.
	MaxLoginFailures = 5
	// LockoutBase is the first lock; each further failure doubles it.
	LockoutBase = time.Minute
	// LockoutMax caps the backoff.
	LockoutMax = time.Hour
	// HashWait is how long a sign-in waits for an argon2id slot before it
	// is answered "busy".
	HashWait = 200 * time.Millisecond
	// maxLockEntries bounds the lockout table; stale entries go first.
	maxLockEntries = 10000
)

// errBusy marks a refusal because every hashing slot is taken.
var errBusy = errors.New("sign-in busy")

// IsBusy reports whether err is the hashing-slots-full refusal. The surface
// answers it 503 with Retry-After.
func IsBusy(err error) bool { return errors.Is(err, errBusy) }

func busy() error {
	return errors.Join(&resource.Error{Code: resource.CodeUnavailable, Message: "sign-in is busy; retry shortly"}, errBusy)
}

// lockFor is the lock after failures failed sign-ins in a row.
func lockFor(failures int) time.Duration {
	if failures < MaxLoginFailures {
		return 0
	}
	shift := min(failures-MaxLoginFailures, 16)
	return min(LockoutBase<<shift, LockoutMax)
}

type lockout struct {
	failures int
	until    time.Time
	last     time.Time
}

// guard bounds argon2id work and tracks failures per user and address.
type guard struct {
	slots chan struct{}
	mu    sync.Mutex
	locks map[string]*lockout
	log   *slog.Logger
}

func newGuard() *guard {
	return &guard{slots: make(chan struct{}, max(2, runtime.NumCPU()/2)), locks: map[string]*lockout{}, log: slog.New(slog.DiscardHandler)}
}

// hash runs fn in a hashing slot, or returns busy after HashWait.
func (g *guard) hash(ctx context.Context, fn func()) error {
	t := time.NewTimer(HashWait)
	defer t.Stop()
	select {
	case g.slots <- struct{}{}:
	case <-t.C:
		return busy()
	case <-ctx.Done():
		return busy()
	}
	defer func() { <-g.slots }()
	fn()
	return nil
}

func lockKey(a resource.AccountID, user, ip string) string { return a.String() + "/" + user + "@" + ip }

func (g *guard) locked(key string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	l := g.locks[key]
	return l != nil && now.Before(l.until)
}

// fail records a failure and locks with backoff; the lock is logged without
// secrets.
func (g *guard) fail(ctx context.Context, req LoginRequest, now time.Time) {
	key := lockKey(req.Account, req.UserName, req.SourceIP)
	g.mu.Lock()
	defer g.mu.Unlock()
	l := g.locks[key]
	if l == nil {
		g.prune(now)
		l = &lockout{}
		g.locks[key] = l
	}
	l.failures++
	l.last = now
	if d := lockFor(l.failures); d > 0 {
		l.until = now.Add(d)
		g.log.LogAttrs(ctx, slog.LevelWarn, "console sign-in locked out",
			slog.String("account", req.Account.String()), slog.String("user", req.UserName),
			slog.String("source_ip", req.SourceIP), slog.Int("failures", l.failures), slog.Time("until", l.until))
	}
}

func (g *guard) succeed(req LoginRequest) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.locks, lockKey(req.Account, req.UserName, req.SourceIP))
}

// forget clears every lock for a user (a new password was set).
func (g *guard) forget(a resource.AccountID, user string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	prefix := a.String() + "/" + user + "@"
	for k := range g.locks {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(g.locks, k)
		}
	}
}

// prune drops entries idle longer than LockoutMax once the table is full,
// then the oldest, so spraying addresses cannot grow it without bound.
func (g *guard) prune(now time.Time) {
	if len(g.locks) < maxLockEntries {
		return
	}
	for k, l := range g.locks {
		if now.Sub(l.last) > LockoutMax && !now.Before(l.until) {
			delete(g.locks, k)
		}
	}
	for len(g.locks) >= maxLockEntries {
		var oldest string
		var at time.Time
		for k, l := range g.locks {
			if oldest == "" || l.last.Before(at) {
				oldest, at = k, l.last
			}
		}
		delete(g.locks, oldest)
	}
}

// LimitHashing sets how many argon2id hashes may run at once (tests, tuning).
func (f *Fake) LimitHashing(n int) { f.guard.slots = make(chan struct{}, max(1, n)) }

// LimitHashing sets how many argon2id hashes may run at once.
func (s *Static) LimitHashing(n int) { s.guard.slots = make(chan struct{}, max(1, n)) }

// OccupyHashing takes every hashing slot until release is called (tests).
func (f *Fake) OccupyHashing() (release func()) {
	n := cap(f.guard.slots)
	for range n {
		f.guard.slots <- struct{}{}
	}
	return func() {
		for range n {
			<-f.guard.slots
		}
	}
}

// SetLogger sets where lockout notices go.
func (f *Fake) SetLogger(l *slog.Logger) { f.guard.log = l }

// SetLogger sets where lockout notices go.
func (s *Static) SetLogger(l *slog.Logger) { s.guard.log = l }
