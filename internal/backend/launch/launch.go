// Package launch records the side effects of one RunInstances, so a failed or
// interrupted launch can be undone or resumed (#392). A record is written
// only when a step completes or the phase changes.
package launch

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Phase is where a launch stands.
type Phase string

// The launch phases. Succeeded is final: a later failure of a replay does
// not undo a launch that once succeeded.
const (
	Running   Phase = "running"
	Succeeded Phase = "succeeded"
	Failed    Phase = "failed"
)

// StepKind names the side effect a step made.
type StepKind string

// The launch steps, in the order RunInstances makes them for each instance.
const (
	StepVolume   StepKind = "volume"
	StepInstance StepKind = "instance"
)

// Step is one side effect: the backend resource name of the boot volume or
// instance at Index of the launch.
type Step struct {
	Kind     StepKind `json:"kind"`
	Index    int      `json:"index"`
	Resource string   `json:"resource"`
}

// Record is one launch. Key is the idempotency key of the client token
// (account, action and token), so the token itself is never stored. Plan is
// every resource the launch may create, written before the first create, so
// a create whose step was never recorded (a crash, a failed record write) is
// still named. Steps are the creates that completed. Attempt counts the
// retries that moved a failed launch back to running.
type Record struct {
	Key         string             `json:"key"`
	Account     resource.AccountID `json:"account"`
	Fingerprint string             `json:"fingerprint"`
	Count       int                `json:"count"`
	Phase       Phase              `json:"phase"`
	Attempt     int                `json:"attempt"`
	Plan        []Step             `json:"plan"`
	Steps       []Step             `json:"steps"`
	Started     time.Time          `json:"started"`
	Updated     time.Time          `json:"updated"`
}

// ErrExists is a Create of a key that already has a record.
var ErrExists = errors.New("launch record exists")

// ErrConflict is an Update whose version is no longer the stored one.
var ErrConflict = errors.New("launch record changed")

// Store keeps records. Every write is a compare-and-swap: Create fails with
// ErrExists and Update with ErrConflict instead of overwriting.
type Store interface {
	Load(ctx context.Context, key string) (rec Record, version string, found bool, err error)
	Create(ctx context.Context, rec Record) (version string, err error)
	Update(ctx context.Context, rec Record, version string) (next string, err error)
}

// writeTimeout bounds a Done or Finish write, which outlives the request:
// the create it records happened whether or not the client still waits.
const writeTimeout = 10 * time.Second

// conflictRetries bounds how often a write reloads after a concurrent
// request with the same client token changed the record.
const conflictRetries = 5

// Tracker writes launch records through a Store. A nil Tracker records
// nothing, for a backend that runs without a launch store.
type Tracker struct {
	store Store
	now   func() time.Time
}

// NewTracker returns a Tracker over store. A nil now is the wall clock.
func NewTracker(store Store, now func() time.Time) *Tracker {
	if now == nil {
		now = time.Now
	}
	return &Tracker{store: store, now: now}
}

// Launch is one launch's record as this request last saw it. The zero
// Launch, from a nil Tracker, records nothing.
type Launch struct {
	t       *Tracker
	rec     Record
	version string
	// attempt is the Record.Attempt this request runs as. A request whose
	// attempt a retry has replaced cannot mark the launch failed.
	attempt int
}

// Record returns the record as last written or read.
func (l *Launch) Record() Record { return l.rec }

// Begin returns the launch for key. An absent record is created Running
// with plan, the resources of count instances. A retry of a failed launch
// moves it back to Running as a new attempt; a retry of a running or
// succeeded launch writes nothing. A record with another fingerprint or
// count is the client token reused with other parameters.
func (t *Tracker) Begin(
	ctx context.Context, key string, account resource.AccountID, fingerprint string, count int, plan []Step,
) (Launch, error) {
	if t == nil {
		return Launch{}, nil
	}
	now := t.now().UTC()
	rec := Record{
		Key: key, Account: account, Fingerprint: fingerprint, Count: count,
		Phase: Running, Attempt: 1, Plan: slices.Clone(plan), Steps: []Step{}, Started: now, Updated: now,
	}
	for range conflictRetries {
		version, err := t.store.Create(ctx, rec)
		if err == nil {
			return Launch{t: t, rec: rec, version: version, attempt: 1}, nil
		}
		if !errors.Is(err, ErrExists) {
			return Launch{}, unavailable(err)
		}
		l, found, err := t.load(ctx, key)
		if err != nil {
			return Launch{}, err
		}
		if !found {
			continue
		}
		if l.rec.Account != account || l.rec.Fingerprint != fingerprint || l.rec.Count != count {
			return Launch{}, resource.IdempotencyMismatch()
		}
		err = l.apply(ctx, func(r *Record) bool {
			if r.Phase != Failed {
				return false
			}
			r.Phase = Running
			r.Attempt++
			return true
		})
		l.attempt = l.rec.Attempt
		return l, err
	}
	return Launch{}, unavailable(fmt.Errorf("begin %s: %w", key, ErrConflict))
}

// Done records a completed step. A step already recorded writes nothing.
func (l *Launch) Done(ctx context.Context, step Step) error {
	if l.t == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	return l.apply(ctx, func(r *Record) bool {
		if slices.Contains(r.Steps, step) {
			return false
		}
		r.Steps = append(r.Steps, step)
		return true
	})
}

// Finish moves the launch to phase. A launch already in phase, or one that
// succeeded, writes nothing. Failed is written only by the latest attempt:
// a stale request never fails a retry that is still running.
func (l *Launch) Finish(ctx context.Context, phase Phase) error {
	if l.t == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	return l.apply(ctx, func(r *Record) bool {
		if !finishes(r.Phase, phase) || (phase == Failed && r.Attempt != l.attempt) {
			return false
		}
		r.Phase = phase
		return true
	})
}

// finishes reports whether a launch in from may end in to.
func finishes(from, to Phase) bool {
	switch from {
	case Running:
		return to == Succeeded || to == Failed
	case Failed:
		return to == Succeeded
	case Succeeded:
		return false
	}
	return false
}

// apply changes the record with change and writes it when change reports a
// difference. On a conflict it reloads and applies change again, so two
// requests with one client token both land their steps.
func (l *Launch) apply(ctx context.Context, change func(*Record) bool) error {
	for range conflictRetries {
		next := l.rec
		next.Steps = slices.Clone(l.rec.Steps)
		next.Plan = slices.Clone(l.rec.Plan)
		if !change(&next) {
			return nil
		}
		next.Updated = l.t.now().UTC()
		version, err := l.t.store.Update(ctx, next, l.version)
		if err == nil {
			l.rec, l.version = next, version
			return nil
		}
		if !errors.Is(err, ErrConflict) {
			return unavailable(err)
		}
		fresh, found, err := l.t.load(ctx, l.rec.Key)
		if err != nil {
			return err
		}
		if !found {
			return unavailable(fmt.Errorf("launch %s: record removed", l.rec.Key))
		}
		l.rec, l.version = fresh.rec, fresh.version
	}
	return unavailable(fmt.Errorf("launch %s: %w", l.rec.Key, ErrConflict))
}

func (t *Tracker) load(ctx context.Context, key string) (Launch, bool, error) {
	rec, version, found, err := t.store.Load(ctx, key)
	if err != nil {
		return Launch{}, false, unavailable(err)
	}
	return Launch{t: t, rec: rec, version: version, attempt: rec.Attempt}, found, nil
}

// unavailable is a store failure. The launch did not record its step, so the
// caller fails the request and a retry with the same token resumes it.
func unavailable(err error) error {
	return (&resource.Error{Code: resource.CodeUnavailable, Message: "launch record unavailable"}).WithCause(err)
}
