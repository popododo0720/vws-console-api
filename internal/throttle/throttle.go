// Package throttle limits EC2 API requests the way EC2 does: a token bucket
// per account and per action, sized by the action's class
// (https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-throttling.html).
// One Limiter serves every surface, so the EC2 Query and console calls of
// one account share its buckets. Buckets live in memory and start full after
// a restart.
package throttle

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Class groups actions that share a bucket size.
type Class int

// Classes, after the EC2 categories.
const (
	// ClassDescribe is a read: Describe*, Get* and List*.
	ClassDescribe Class = iota + 1
	// ClassMutate is any other EC2 action.
	ClassMutate
	// ClassLaunch is RunInstances and StartInstances, which EC2 gives its
	// smallest request bucket because each one starts machines.
	ClassLaunch
)

// ClassOf classifies an IAM action such as "ec2:RunInstances". Only ec2 and
// vws (operation polling) actions are limited here; any other service
// reports false.
func ClassOf(iamAction string) (Class, bool) {
	service, name, ok := strings.Cut(iamAction, ":")
	if !ok || (service != "ec2" && service != "vws") || name == "" {
		return 0, false
	}
	switch {
	case name == resource.ActionRunInstances.String() || name == resource.ActionStartInstances.String():
		return ClassLaunch, true
	case strings.HasPrefix(name, "Describe"), strings.HasPrefix(name, "Get"), strings.HasPrefix(name, "List"):
		return ClassDescribe, true
	default:
		return ClassMutate, true
	}
}

// Rate is one bucket: Burst tokens, refilled at PerSecond.
type Rate struct {
	Burst     int
	PerSecond float64
}

// Limits sizes the buckets of each class.
type Limits struct {
	Describe Rate
	Mutate   Rate
	Launch   Rate
	// MaxKeys bounds the (account, action) table, so many accounts cannot
	// grow memory without bound.
	MaxKeys int
}

// Bounds a Limits field must stay within.
const (
	maxBurst     = 100000
	minPerSecond = 0.01
	maxPerSecond = 100000
	minMaxKeys   = 100
	maxMaxKeys   = 10000000
)

// DefaultLimits returns the EC2 defaults: non-mutating 100 tokens refilled
// at 20 a second, mutating 50 at 5, RunInstances and StartInstances 5 at 2.
// MaxKeys holds 100000 (account, action) buckets.
func DefaultLimits() Limits {
	return Limits{
		Describe: Rate{Burst: 100, PerSecond: 20},
		Mutate:   Rate{Burst: 50, PerSecond: 5},
		Launch:   Rate{Burst: 5, PerSecond: 2},
		MaxKeys:  100000,
	}
}

// Validate reports the first field outside its bounds: bursts 1 to 100000,
// rates 0.01 to 100000 a second, MaxKeys 100 to 10000000.
func (l Limits) Validate() error {
	for _, c := range []Class{ClassDescribe, ClassMutate, ClassLaunch} {
		r := l.rate(c)
		if r.Burst < 1 || r.Burst > maxBurst {
			return fmt.Errorf("%s burst %d: want 1 to %d", c, r.Burst, maxBurst)
		}
		if !(r.PerSecond >= minPerSecond && r.PerSecond <= maxPerSecond) {
			return fmt.Errorf("%s rate %g: want %g to %d a second", c, r.PerSecond, minPerSecond, maxPerSecond)
		}
	}
	if l.MaxKeys < minMaxKeys || l.MaxKeys > maxMaxKeys {
		return fmt.Errorf("max keys %d: want %d to %d", l.MaxKeys, minMaxKeys, maxMaxKeys)
	}
	return nil
}

func (l Limits) rate(c Class) Rate {
	switch c {
	case ClassDescribe:
		return l.Describe
	case ClassMutate:
		return l.Mutate
	case ClassLaunch:
		return l.Launch
	}
	return Rate{}
}

func (c Class) String() string {
	switch c {
	case ClassDescribe:
		return "describe"
	case ClassMutate:
		return "mutate"
	case ClassLaunch:
		return "launch"
	}
	return "unknown"
}

// Limiter holds one bucket per account and action.
type Limiter struct {
	limits Limits
	now    func() time.Time

	mu      sync.Mutex
	buckets map[string]*rate.Limiter
}

// New returns a Limiter. limits must pass Validate. A nil now uses
// time.Now.
func New(limits Limits, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{limits: limits, now: now, buckets: map[string]*rate.Limiter{}}
}

// Take spends one token of account's bucket for iamAction. Over the limit it
// returns RequestLimitExceeded and how long until the next token. An action
// ClassOf does not limit, and a nil Limiter, always pass.
func (l *Limiter) Take(account resource.AccountID, iamAction string) (time.Duration, error) {
	if l == nil {
		return 0, nil
	}
	class, ok := ClassOf(iamAction)
	if !ok {
		return 0, nil
	}
	r := l.limits.rate(class)
	key := account.String() + "/" + iamAction
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= l.limits.MaxKeys {
			l.prune(now)
		}
		b = rate.NewLimiter(rate.Limit(r.PerSecond), r.Burst)
		l.buckets[key] = b
	}
	if b.AllowN(now, 1) {
		return 0, nil
	}
	wait := time.Duration((1 - b.TokensAt(now)) / r.PerSecond * float64(time.Second))
	return wait, resource.RequestLimitExceeded()
}

// size is the number of buckets held (tests).
func (l *Limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// prune drops full buckets, which act the same as a new one, then arbitrary
// ones until there is room. Dropping a partly drained bucket refills it, so
// pruning only ever errs toward letting a request through.
func (l *Limiter) prune(now time.Time) {
	for k, b := range l.buckets {
		if b.TokensAt(now) >= float64(b.Burst()) {
			delete(l.buckets, k)
		}
	}
	for k := range l.buckets {
		if len(l.buckets) < l.limits.MaxKeys {
			break
		}
		delete(l.buckets, k)
	}
}
