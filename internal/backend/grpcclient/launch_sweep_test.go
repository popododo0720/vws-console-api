package grpcclient

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/popododo0720/vws-console-api/internal/backend/launch"
)

// process is one console-api process over the shared launch world and
// launch store. Once killed, its connection is closed and its store calls
// fail, as for a process that died between two calls.
type process struct {
	store    launch.Store
	conn     *grpc.ClientConn
	dead     atomic.Bool
	mu       sync.Mutex
	writes   int
	dieAfter int
}

var errDead = errors.New("process killed")

func (f launchFixture) process(t *testing.T) (*process, launchFixture) {
	t.Helper()
	client, conn := f.boot.dial(t)
	p := &process{store: f.store, conn: conn}
	client.launches = launch.NewTracker(p, nil)
	dying := f
	dying.client = client
	return p, dying
}

func (p *process) kill() {
	p.dead.Store(true)
	_ = p.conn.Close()
}

func (p *process) wrote() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writes++
	if p.writes == p.dieAfter {
		p.kill()
	}
}

func (p *process) Load(ctx context.Context, key string) (launch.Record, string, bool, error) {
	if p.dead.Load() {
		return launch.Record{}, "", false, errDead
	}
	return p.store.Load(ctx, key)
}

func (p *process) Unfinished(ctx context.Context) ([]launch.Stored, error) {
	if p.dead.Load() {
		return nil, errDead
	}
	return p.store.Unfinished(ctx)
}

func (p *process) Create(ctx context.Context, rec launch.Record) (string, error) {
	if p.dead.Load() {
		return "", errDead
	}
	v, err := p.store.Create(ctx, rec)
	if err == nil {
		p.wrote()
	}
	return v, err
}

func (p *process) Update(ctx context.Context, rec launch.Record, version string) (string, error) {
	if p.dead.Load() {
		return "", errDead
	}
	v, err := p.store.Update(ctx, rec, version)
	if err == nil {
		p.wrote()
	}
	return v, err
}

// TestCrashAfterEveryStepIsResumedOrSwept pins #392 AC 3: a process killed
// after any create or record write of a two-instance launch leaves the
// launch running or undoing. Another process either resumes it, by a retry
// with the same token, or undoes it, by the sweep once the launch has been
// idle for launchIdle, and the sweep leaves a launch written since alone.
// After either, a retry launches both instances, a second retry returns the
// same instances, and nothing of an undone attempt is left.
func TestCrashAfterEveryStepIsResumedOrSwept(t *testing.T) {
	cases := []struct {
		name  string
		crash func(f launchFixture, p *process)
	}{
		{"after the record", func(_ launchFixture, p *process) { p.dieAfter = 1 }},
		{"first volume", func(f launchFixture, p *process) { f.boot.crashAt("CreateVolume", 1, p.kill) }},
		{"first volume step", func(_ launchFixture, p *process) { p.dieAfter = 2 }},
		{"first instance", func(f launchFixture, p *process) { f.boot.crashAt("CreateInstance", 1, p.kill) }},
		{"first instance step", func(_ launchFixture, p *process) { p.dieAfter = 3 }},
		{"second volume", func(f launchFixture, p *process) { f.boot.crashAt("CreateVolume", 2, p.kill) }},
		{"second volume step", func(_ launchFixture, p *process) { p.dieAfter = 4 }},
		{"second instance", func(f launchFixture, p *process) { f.boot.crashAt("CreateInstance", 2, p.kill) }},
		{"last step", func(_ launchFixture, p *process) { p.dieAfter = 5 }},
		{"undoing", func(f launchFixture, p *process) {
			f.boot.failAt("CreateInstance", 1, false)
			p.dieAfter = 3
		}},
	}
	for _, tc := range cases {
		for _, sweep := range []bool{false, true} {
			name := tc.name + "/retry"
			if sweep {
				name = tc.name + "/sweep"
			}
			t.Run(name, func(t *testing.T) {
				f := newLaunch(t, "crash-"+name)
				p, dying := f.process(t)
				tc.crash(f, p)
				if _, err := dying.launch(t, 2); err == nil {
					t.Fatal("the killed launch succeeded")
				}
				if !p.dead.Load() {
					t.Fatal("the process was not killed")
				}
				if rec := f.record(t); rec.Phase != launch.Running && rec.Phase != launch.Undoing {
					t.Fatalf("killed launch recorded %+v", rec)
				}
				if sweep {
					ctx := context.Background()
					if n, err := f.client.sweepLaunches(ctx); n != 0 || err != nil {
						t.Fatalf("swept %d launches written just now, err %v", n, err)
					}
					f.client.launches = launch.NewTracker(f.store, func() time.Time { return time.Now().Add(launchIdle) })
					if n, err := f.client.sweepLaunches(ctx); n != 1 || err != nil {
						t.Fatalf("swept %d launches err %v, want 1", n, err)
					}
					f.assertNothingLeft(t)
					if rec := f.record(t); rec.Phase != launch.Failed {
						t.Fatalf("swept launch recorded %+v", rec)
					}
					if n, err := f.client.sweepLaunches(ctx); n != 0 || err != nil {
						t.Fatalf("second sweep undid %d err %v", n, err)
					}
				}
				first, err := f.launch(t, 2)
				if err != nil {
					t.Fatal(err)
				}
				again, err := f.launch(t, 2)
				if err != nil || !slices.Equal(first, again) || len(first) != 2 {
					t.Fatalf("retry %v then %v err %v", first, again, err)
				}
				if v, i, ips := f.boot.left(); v != 2 || i != 2 || ips != 2 {
					t.Fatalf("live volumes %d instances %d ips %d want 2 each", v, i, ips)
				}
				if rec := f.record(t); rec.Phase != launch.Succeeded {
					t.Fatalf("retried record %+v", rec)
				}
			})
		}
	}
}

// TestOneSweepUndoesMoreLaunchesThanItRunsAtOnce pins that a sweep that
// finds more abandoned launches than sweepParallel undoes all of them.
func TestOneSweepUndoesMoreLaunchesThanItRunsAtOnce(t *testing.T) {
	f := newLaunch(t, "crowd")
	for i := range sweepParallel + 5 {
		p, dying := f.process(t)
		dying.m.Key = "crowd-" + strconv.Itoa(i)
		p.dieAfter = 2
		if _, err := dying.launch(t, 1); err == nil {
			t.Fatal("the killed launch succeeded")
		}
	}
	if v, _, _ := f.boot.left(); v != sweepParallel+5 {
		t.Fatalf("killed launches left %d volumes", v)
	}
	f.client.launches = launch.NewTracker(f.store, func() time.Time { return time.Now().Add(launchIdle) })
	if n, err := f.client.sweepLaunches(context.Background()); n != sweepParallel+5 || err != nil {
		t.Fatalf("swept %d err %v want %d", n, err, sweepParallel+5)
	}
	f.assertNothingLeft(t)
}
