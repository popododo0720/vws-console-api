package grpcclient

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend/launch"
)

// lateCreate makes the boot volume and instance of index i of attempt as a
// create the backend applied after its request gave up, so no step records
// it and the undo of that attempt never sees it.
func (f launchFixture) lateCreate(t *testing.T, attempt, i int) {
	t.Helper()
	ctx := context.Background()
	projectID := project(f.m.Account)
	volID := bootVolumeID(f.m.Key, attempt, i)
	if _, err := f.boot.CreateVolume(ctx, &storagev1.CreateVolumeRequest{
		Parent: volumeParent(projectID), VolumeId: volID, RequestId: "late-vol-" + volID,
	}); err != nil {
		t.Fatal(err)
	}
	instID := launchInstanceID(f.m.Key, attempt, i)
	if _, err := f.boot.CreateInstance(ctx, &computev1.CreateInstanceRequest{
		Parent: instanceParent(projectID), InstanceId: instID, RequestId: "late-inst-" + instID,
		Instance: &computev1.Instance{Spec: &computev1.InstanceSpec{
			Volumes: []*computev1.VolumeAttachment{{Volume: volumeName(projectID, volID), Boot: true}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
}

// idle makes the fixture's tracker run n times launchIdle ahead, so a
// record written before is idle, and so is one written by the last idle.
func (f *launchFixture) idle(n int) {
	f.client.launches = launch.NewTracker(f.store, func() time.Time {
		return time.Now().Add(time.Duration(n) * launchIdle)
	})
}

func (f launchFixture) deletes() int {
	f.boot.mu.Lock()
	defer f.boot.mu.Unlock()
	return len(f.boot.deletes)
}

// TestGCRemovesALateCreateOfAFailedLaunch pins #392 AC 4: a volume,
// instance and IP that a failed launch's create left after its undo are
// deleted by the launch GC once the launch is idle, and the launch is
// recorded collected. A second pass sends no delete and writes nothing.
func TestGCRemovesALateCreateOfAFailedLaunch(t *testing.T) {
	f := newLaunch(t, "gc-failed")
	f.boot.failAt("CreateInstance", 2, false)
	if _, err := f.launch(t, 2); err == nil {
		t.Fatal("the failing launch succeeded")
	}
	f.lateCreate(t, 1, 1)
	if v, i, ips := f.boot.left(); v != 1 || i != 1 || ips != 1 {
		t.Fatalf("late create left volumes %d instances %d ips %d", v, i, ips)
	}
	ctx := context.Background()
	if n, err := f.client.collectLaunches(ctx); n != 0 || err != nil {
		t.Fatalf("collected %d launches written just now, err %v", n, err)
	}
	f.idle(1)
	if n, err := f.client.collectLaunches(ctx); n != 1 || err != nil {
		t.Fatalf("collected %d err %v want 1", n, err)
	}
	f.assertNothingLeft(t)
	if rec := f.record(t); rec.Phase != launch.Failed || rec.Collected != 1 {
		t.Fatalf("collected record %+v", rec)
	}
	deletes, writes := f.deletes(), f.store.Writes()
	if n, err := f.client.collectLaunches(ctx); n != 0 || err != nil {
		t.Fatalf("second pass collected %d err %v", n, err)
	}
	if f.deletes() != deletes || f.store.Writes() != writes {
		t.Fatalf("second pass sent %d deletes and %d writes", f.deletes()-deletes, f.store.Writes()-writes)
	}
}

// TestGCKeepsTheSucceededAttempt pins that the GC deletes what an earlier
// attempt left and never a resource of the attempt that succeeded.
func TestGCKeepsTheSucceededAttempt(t *testing.T) {
	f := newLaunch(t, "gc-succeeded")
	f.boot.failAt("CreateInstance", 1, false)
	if _, err := f.launch(t, 2); err == nil {
		t.Fatal("the failing launch succeeded")
	}
	f.lateCreate(t, 1, 0)
	f.lateCreate(t, 1, 1)
	launched, err := f.launch(t, 2)
	if err != nil {
		t.Fatal(err)
	}
	f.idle(1)
	if n, err := f.client.collectLaunches(context.Background()); n != 1 || err != nil {
		t.Fatalf("collected %d err %v want 1", n, err)
	}
	if v, i, ips := f.boot.left(); v != 2 || i != 2 || ips != 2 {
		t.Fatalf("live volumes %d instances %d ips %d want the 2 launched", v, i, ips)
	}
	again, err := f.launch(t, 2)
	if err != nil || !slices.Equal(launched, again) {
		t.Fatalf("retry after GC %v err %v want %v", again, err, launched)
	}
	if rec := f.record(t); rec.Phase != launch.Succeeded || rec.Attempt != 2 || rec.Collected != 1 {
		t.Fatalf("record %+v", rec)
	}
}

// TestGCNeverTouchesARunningLaunch pins that the GC sends no delete for a
// running launch, even an idle one with an earlier attempt's leftovers:
// the sweep ends it first, and the GC collects it once that is idle too.
func TestGCNeverTouchesARunningLaunch(t *testing.T) {
	f := newLaunch(t, "gc-running")
	f.boot.failAt("CreateInstance", 1, false)
	if _, err := f.launch(t, 1); err == nil {
		t.Fatal("the failing launch succeeded")
	}
	f.lateCreate(t, 1, 0)
	p, dying := f.process(t)
	p.dieAfter = 2
	if _, err := dying.launch(t, 1); err == nil {
		t.Fatal("the killed launch succeeded")
	}
	if rec := f.record(t); rec.Phase != launch.Running || rec.Attempt != 2 {
		t.Fatalf("killed retry recorded %+v", rec)
	}
	f.idle(1)
	ctx := context.Background()
	deletes := f.deletes()
	if n, err := f.client.collectLaunches(ctx); n != 0 || err != nil {
		t.Fatalf("collected %d running launches err %v", n, err)
	}
	if f.deletes() != deletes {
		t.Fatalf("GC sent %d deletes for a running launch", f.deletes()-deletes)
	}
	if v, i, _ := f.boot.left(); v != 2 || i != 1 {
		t.Fatalf("running launch left volumes %d instances %d want 2 and 1", v, i)
	}
	if n, err := f.client.sweepLaunches(ctx); n != 1 || err != nil {
		t.Fatalf("swept %d err %v want 1", n, err)
	}
	if n, err := f.client.collectLaunches(ctx); n != 0 || err != nil {
		t.Fatalf("collected %d launches the sweep just failed, err %v", n, err)
	}
	f.idle(2)
	if n, err := f.client.collectLaunches(ctx); n != 1 || err != nil {
		t.Fatalf("collected %d err %v want 1", n, err)
	}
	f.assertNothingLeft(t)
	if rec := f.record(t); rec.Phase != launch.Failed || rec.Collected != 2 {
		t.Fatalf("record %+v", rec)
	}
}

// TestGCCutShortIsFinishedByTheNextPass pins that a GC pass that cannot
// delete, or cannot record what it deleted, leaves the launch to collect,
// and the next pass finishes it.
func TestGCCutShortIsFinishedByTheNextPass(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault func(f launchFixture)
	}{
		{"delete", func(f launchFixture) {
			f.boot.mu.Lock()
			next := f.boot.calls["DeleteInstance"] + 1
			f.boot.mu.Unlock()
			f.boot.failFor("DeleteInstance", next, undoAttempts)
		}},
		{"record", func(f launchFixture) { f.store.FailAfter(0, errors.New("api server down")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLaunch(t, "gc-cut-"+tc.name)
			f.boot.failAt("CreateInstance", 1, false)
			if _, err := f.launch(t, 1); err == nil {
				t.Fatal("the failing launch succeeded")
			}
			f.lateCreate(t, 1, 0)
			f.idle(1)
			tc.fault(f)
			ctx := context.Background()
			if n, err := f.client.collectLaunches(ctx); n != 0 || err == nil {
				t.Fatalf("broken pass collected %d err %v", n, err)
			}
			if rec := f.record(t); rec.Collected != 0 {
				t.Fatalf("broken pass recorded %+v", rec)
			}
			if n, err := f.client.collectLaunches(ctx); n != 1 || err != nil {
				t.Fatalf("next pass collected %d err %v", n, err)
			}
			f.assertNothingLeft(t)
			if rec := f.record(t); rec.Collected != 1 {
				t.Fatalf("record %+v", rec)
			}
		})
	}
}

// TestRetryAfterTheGCListedALaunchKeepsTheRunningAttempt pins the race the
// GC cannot exclude: a retry moves a listed failed launch back to running
// before the GC deletes. The GC deletes the dead attempt only, and the
// running attempt's volume is left.
func TestRetryAfterTheGCListedALaunchKeepsTheRunningAttempt(t *testing.T) {
	f := newLaunch(t, "gc-race")
	f.boot.failAt("CreateInstance", 1, false)
	if _, err := f.launch(t, 1); err == nil {
		t.Fatal("the failing launch succeeded")
	}
	f.lateCreate(t, 1, 0)
	f.idle(1)
	ctx := context.Background()
	listed, err := f.client.launches.Collectable(ctx, launchIdle)
	if err != nil || len(listed) != 1 {
		t.Fatalf("listed %d err %v", len(listed), err)
	}
	p, dying := f.process(t)
	p.dieAfter = 2
	if _, err := dying.launch(t, 1); err == nil {
		t.Fatal("the killed retry succeeded")
	}
	if err := f.client.collectAttempts(ctx, &listed[0]); err != nil {
		t.Fatal(err)
	}
	if v, i, _ := f.boot.left(); v != 1 || i != 0 {
		t.Fatalf("left volumes %d instances %d want the running attempt's volume only", v, i)
	}
	f.boot.mu.Lock()
	_, kept := f.boot.volumes[volumeName(project(f.m.Account), bootVolumeID(f.m.Key, 2, 0))]
	f.boot.mu.Unlock()
	if !kept {
		t.Fatal("the GC deleted the running attempt's volume")
	}
	if rec := f.record(t); rec.Phase != launch.Running || rec.Attempt != 2 || rec.Collected != 1 {
		t.Fatalf("record %+v", rec)
	}
}
