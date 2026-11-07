package grpcclient

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/launch"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// launchFixture is a client over a launchWorld with a launch tracker over an
// in-memory store.
type launchFixture struct {
	boot   *launchWorld
	client computeClient
	store  *launch.Memory
	m      backend.Mutation
}

func newLaunch(t *testing.T, key string) launchFixture {
	t.Helper()
	boot, client := startLaunchWorld(t)
	store := &launch.Memory{}
	client.launches = launch.NewTracker(store, nil)
	m := backend.Mutation{Scope: backend.Scope{Account: mustAccount(t)}, Key: key, Fingerprint: "fp"}
	return launchFixture{boot: boot, client: client, store: store, m: m}
}

func (f launchFixture) run(t *testing.T, count int) error {
	t.Helper()
	sub, err := resource.Parse[resource.SubnetID]("subnet-01234567")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.client.RunInstances(context.Background(), f.m, resource.RunInstancesRequest{
		ImageID: mustImage(t, catalogAMI), InstanceType: "vws.small", SubnetID: sub, Count: count,
	})
	return err
}

func (f launchFixture) record(t *testing.T) launch.Record {
	t.Helper()
	rec, _, found, err := f.store.Load(context.Background(), f.m.Key)
	if err != nil || !found {
		t.Fatalf("record found %v err %v", found, err)
	}
	return rec
}

func (f launchFixture) plan(attempt, count int) []launch.Step {
	return launchPlan(project(f.m.Account), f.m.Key, attempt, count)
}

func (f launchFixture) created() (volumes, instances int) {
	f.boot.mu.Lock()
	defer f.boot.mu.Unlock()
	return f.boot.made["CreateVolume"], f.boot.made["CreateInstance"]
}

// assertNothingLeft fails when a volume, instance or private IP is live.
func (f launchFixture) assertNothingLeft(t *testing.T) {
	t.Helper()
	if v, i, ips := f.boot.left(); v != 0 || i != 0 || ips != 0 {
		t.Fatalf("left volumes %d instances %d ips %d", v, i, ips)
	}
}

// TestRunInstancesRecordsEachStep pins #392: a launch record holds the client
// token's key, the plan and each completed create, in order, and a launch
// that ends writes its phase. Under the vws-deploy#478 rule a write happens
// only on a transition, so the retries write nothing.
func TestRunInstancesRecordsEachStep(t *testing.T) {
	f := newLaunch(t, "launch-ok")
	for i := range 3 {
		if err := f.run(t, 2); err != nil {
			t.Fatalf("try %d: %v", i, err)
		}
	}
	rec := f.record(t)
	if rec.Phase != launch.Succeeded || rec.Account != f.m.Account || rec.Fingerprint != "fp" || rec.Count != 2 {
		t.Fatalf("record %+v", rec)
	}
	if want := f.plan(1, 2); !slices.Equal(rec.Steps, want) || !slices.Equal(rec.Plan, want) {
		t.Fatalf("steps %+v plan %+v want %+v", rec.Steps, rec.Plan, want)
	}
	// The first launch only: one create, four steps and the phase.
	if got := f.store.Writes(); got != 6 {
		t.Fatalf("writes %d want 6", got)
	}
	if v, i, ips := f.boot.left(); v != 2 || i != 2 || ips != 2 {
		t.Fatalf("live volumes %d instances %d ips %d want 2 each", v, i, ips)
	}
}

// TestRunInstancesFailureRecordsCompletedSteps pins that a launch failing at
// its second instance is recorded failed with the steps it completed, after
// they are undone, and a retry with the same key is a second attempt that
// succeeds.
func TestRunInstancesFailureRecordsCompletedSteps(t *testing.T) {
	f := newLaunch(t, "launch-fail")
	f.boot.failAt("CreateInstance", 2, false)
	if err := f.run(t, 2); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("err %v, want unavailable", err)
	}
	if rec, want := f.record(t), f.plan(1, 2)[:3]; rec.Phase != launch.Failed || !slices.Equal(rec.Steps, want) {
		t.Fatalf("record %+v want failed with %+v", rec, want)
	}
	f.assertNothingLeft(t)
	if err := f.run(t, 2); err != nil {
		t.Fatal(err)
	}
	if rec := f.record(t); rec.Phase != launch.Succeeded || rec.Attempt != 2 || !slices.Equal(rec.Steps, f.plan(2, 2)) {
		t.Fatalf("retried record %+v", rec)
	}
}

// TestRunInstancesWithoutARecordCreatesNothing pins that a launch whose
// record cannot be written makes no volume or instance.
func TestRunInstancesWithoutARecordCreatesNothing(t *testing.T) {
	f := newLaunch(t, "launch-down")
	f.store.FailAfter(0, errors.New("api server down"))
	if err := f.run(t, 1); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("err %v, want unavailable", err)
	}
	if v, i := f.created(); v != 0 || i != 0 {
		t.Fatalf("volumes %d instances %d", v, i)
	}
}

// TestRunInstancesTokenReuseIsAMismatch pins that a client token reused with
// other parameters is IdempotentParameterMismatch before any create, and the
// first launch's record is left as it was.
func TestRunInstancesTokenReuseIsAMismatch(t *testing.T) {
	f := newLaunch(t, "launch-reuse")
	if err := f.run(t, 1); err != nil {
		t.Fatal(err)
	}
	writes := f.store.Writes()
	f.m.Fingerprint = "other"
	if err := f.run(t, 1); resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
		t.Fatalf("err %v, want idempotency mismatch", err)
	}
	if v, _ := f.created(); v != 1 || f.store.Writes() != writes {
		t.Fatalf("volumes %d writes %d want 1 and %d", v, f.store.Writes(), writes)
	}
}

// TestPlanNamesACreateWhoseStepWasNotRecorded pins that a volume created
// while its step write failed is still named by the record, so the undo
// deletes it.
func TestPlanNamesACreateWhoseStepWasNotRecorded(t *testing.T) {
	f := newLaunch(t, "launch-lost-step")
	f.store.FailAfter(1, errors.New("api server down"))
	if err := f.run(t, 1); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("err %v, want unavailable", err)
	}
	if rec := f.record(t); rec.Phase != launch.Failed || len(rec.Steps) != 0 || !slices.Equal(rec.Plan, f.plan(1, 1)) {
		t.Fatalf("record %+v want failed, no steps, plan %+v", rec, f.plan(1, 1))
	}
	if v, i := f.created(); v != 1 || i != 0 {
		t.Fatalf("volumes %d instances %d", v, i)
	}
	f.assertNothingLeft(t)
}

// TestFailedSuccessWriteLeavesTheLaunchRunning pins that a launch whose
// creates all succeeded but whose last write failed is never recorded failed:
// a retry finishes it.
func TestFailedSuccessWriteLeavesTheLaunchRunning(t *testing.T) {
	f := newLaunch(t, "launch-last-write")
	f.store.FailAfter(3, errors.New("api server down"))
	if err := f.run(t, 1); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("err %v, want unavailable", err)
	}
	if rec := f.record(t); rec.Phase != launch.Running || len(rec.Steps) != 2 {
		t.Fatalf("record %+v", rec)
	}
	if err := f.run(t, 1); err != nil {
		t.Fatal(err)
	}
	if rec := f.record(t); rec.Phase != launch.Succeeded {
		t.Fatalf("retried phase %s", rec.Phase)
	}
}

// TestLargestLaunchIsRecorded is the boundary case: a launch of the most
// instances RunInstances takes records its whole plan and every step.
func TestLargestLaunchIsRecorded(t *testing.T) {
	f := newLaunch(t, "launch-ten")
	if err := f.run(t, 10); err != nil {
		t.Fatal(err)
	}
	if rec := f.record(t); len(rec.Plan) != 20 || !slices.Equal(rec.Steps, rec.Plan) {
		t.Fatalf("plan %d steps %d want 20", len(rec.Plan), len(rec.Steps))
	}
}
