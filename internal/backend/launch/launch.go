// Package launch records the side effects of one RunInstances, so a failed or
// interrupted launch can be undone or resumed (#392). A record is written
// only when a step completes or the phase changes.
//
// A launch moves running -> succeeded, or running -> undoing -> failed when
// a step fails and its creates are deleted. A retry of a failed launch is a
// new attempt with a new plan, back to running.
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
// not undo a launch that once succeeded. Undoing is written before the first
// delete, so a request that resumes the launch never reuses a deleted
// resource; Failed is written once every planned resource is gone.
const (
	Running   Phase = "running"
	Undoing   Phase = "undoing"
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
// every resource the current attempt may create, written before its first
// create, so a create whose step was never recorded (a crash, a failed record
// write) is still named. Steps are the attempt's creates that completed.
// Attempt counts the retries that moved a failed launch back to running.
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

// Plan names the resources attempt may create. The backend derives their
// ids from the client token and the attempt, so a retry after an undo never
// names a deleted resource. A nil Plan names none.
type Plan func(attempt int) []Step

// Store keeps records. Every write is a compare-and-swap: Create fails with
// ErrExists and Update with ErrConflict instead of overwriting.
type Store interface {
	Load(ctx context.Context, key string) (rec Record, version string, found bool, err error)
	Unfinished(ctx context.Context) ([]Stored, error)
	Create(ctx context.Context, rec Record) (version string, err error)
	Update(ctx context.Context, rec Record, version string) (next string, err error)
}

// Stored is a record with the version it was read at. Unfinished returns
// every record that is running or undoing, and may return others too.
type Stored struct {
	Record  Record
	Version string
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
	// idleSince is set on a launch the sweep found abandoned: Undo claims
	// it only while its record was last written at or before idleSince.
	idleSince time.Time
}

// Record returns the record as last written or read.
func (l *Launch) Record() Record { return l.rec }

// Attempt is the attempt this request runs as, 0 without a tracker.
func (l *Launch) Attempt() int { return l.attempt }

// Begin returns the launch for key. An absent record is created Running
// with plan(1), the resources of count instances. A retry of a failed launch
// moves it back to Running as the next attempt with that attempt's plan and
// no steps; a retry of a running, undoing or succeeded launch writes nothing.
// A record with another fingerprint or count is the client token reused with
// other parameters.
func (t *Tracker) Begin(
	ctx context.Context, key string, account resource.AccountID, fingerprint string, count int, plan Plan,
) (Launch, error) {
	if t == nil {
		return Launch{}, nil
	}
	now := t.now().UTC()
	rec := Record{
		Key: key, Account: account, Fingerprint: fingerprint, Count: count,
		Phase: Running, Attempt: 1, Plan: plan.of(1), Steps: []Step{}, Started: now, Updated: now,
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
			r.Plan = plan.of(r.Attempt)
			r.Steps = []Step{}
			return true
		})
		l.attempt = l.rec.Attempt
		return l, err
	}
	return Launch{}, unavailable(fmt.Errorf("begin %s: %w", key, ErrConflict))
}

// Done records a completed step. A step already recorded writes nothing.
// A step of an attempt that another request began to undo, or that a retry
// replaced, writes nothing and is ErrUndone: the caller undoes again, so
// the create it just made is deleted too.
func (l *Launch) Done(ctx context.Context, step Step) error {
	if l.t == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	undone := false
	err := l.apply(ctx, func(r *Record) bool {
		undone = r.Attempt != l.attempt || r.Phase == Undoing || r.Phase == Failed
		if undone || slices.Contains(r.Steps, step) {
			return false
		}
		r.Steps = append(r.Steps, step)
		return true
	})
	if err == nil && undone {
		return l.undoneErr()
	}
	return err
}

func (p Plan) of(attempt int) []Step {
	if p == nil {
		return []Step{}
	}
	return slices.Clone(p(attempt))
}

// Succeed moves this attempt from Running to Succeeded. A launch that
// already succeeded in this attempt writes nothing. A launch that another
// request of this attempt began to undo, or that a later attempt replaced,
// is ErrUndone: the creates this request returns may be gone.
func (l *Launch) Succeed(ctx context.Context) error {
	if l.t == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	undone := false
	err := l.apply(ctx, func(r *Record) bool {
		undone = r.Attempt != l.attempt || (r.Phase != Running && r.Phase != Succeeded)
		if undone || r.Phase == Succeeded {
			return false
		}
		r.Phase = Succeeded
		return true
	})
	if err == nil && undone {
		return l.undoneErr()
	}
	return err
}

// ErrUndone is a step or success of an attempt whose creates are deleted.
var ErrUndone = errors.New("launch attempt undone")

// undoneErr is Unavailable, so a client retries and gets the current attempt.
func (l *Launch) undoneErr() error {
	return unavailable(fmt.Errorf("launch %s attempt %d: %w", l.rec.Key, l.attempt, ErrUndone))
}

// Undo moves this attempt from Running to Undoing and reports whether the
// caller must delete the attempt's plan. An attempt already Undoing or
// Failed reports true without a write, so a request that finds an undo cut
// short resumes it, and one whose create landed after the undo deletes it.
// A launch that succeeded or moved to a later attempt reports false: a
// stale request never deletes another attempt's resources. A launch from
// Abandoned that was written since it went idle reports false too.
func (l *Launch) Undo(ctx context.Context) (bool, error) {
	if l.t == nil {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	undo := false
	err := l.apply(ctx, func(r *Record) bool {
		undo = r.Attempt == l.attempt && r.Phase != Succeeded &&
			(l.idleSince.IsZero() || !r.Updated.After(l.idleSince))
		if !undo || r.Phase != Running {
			return false
		}
		r.Phase = Undoing
		return true
	})
	return undo && err == nil, err
}

// Undone moves this attempt from Undoing to Failed, once the caller deleted
// every resource of the plan. Any other phase or attempt writes nothing.
func (l *Launch) Undone(ctx context.Context) error {
	if l.t == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	return l.apply(ctx, func(r *Record) bool {
		if r.Attempt != l.attempt || r.Phase != Undoing {
			return false
		}
		r.Phase = Failed
		return true
	})
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

// Abandoned returns the launches left running or undoing whose record was
// last written idle or more ago, each as its latest attempt. A store that
// could read only some records returns those launches and its error. A live request
// writes its record on every step, so a launch that idle is one whose request
// died. Undoing one is safe even when its request still runs: that request
// cannot record a step or succeed once the record says undoing.
func (t *Tracker) Abandoned(ctx context.Context, idle time.Duration) ([]Launch, error) {
	if t == nil {
		return nil, nil
	}
	all, listErr := t.store.Unfinished(ctx)
	if listErr != nil {
		listErr = unavailable(listErr)
	}
	cutoff := t.now().Add(-idle)
	var out []Launch
	for _, s := range all {
		if (s.Record.Phase == Running || s.Record.Phase == Undoing) && !s.Record.Updated.After(cutoff) {
			out = append(out, Launch{
				t: t, rec: s.Record, version: s.Version, attempt: s.Record.Attempt, idleSince: cutoff,
			})
		}
	}
	return out, listErr
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
