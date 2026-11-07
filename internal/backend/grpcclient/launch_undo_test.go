package grpcclient

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"

	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend/launch"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (f launchFixture) launch(t *testing.T, count int) ([]resource.InstanceID, error) {
	t.Helper()
	sub, err := resource.Parse[resource.SubnetID]("subnet-01234567")
	if err != nil {
		t.Fatal(err)
	}
	acc, err := f.client.RunInstances(context.Background(), f.m, resource.RunInstancesRequest{
		ImageID: mustImage(t, catalogAMI), InstanceType: "vws.small", SubnetID: sub, Count: count,
	})
	ids := make([]resource.InstanceID, 0, len(acc.Items))
	for _, inst := range acc.Items {
		ids = append(ids, inst.ID)
	}
	return ids, err
}

// TestFailureAtEveryStepIsUndone pins #392: a launch of two instances that
// fails at any create, any read after one, or any record write of a step
// leaves no volume, instance or private IP, and is recorded failed. A retry
// with the same token launches both, and a second retry returns the same
// instances.
func TestFailureAtEveryStepIsUndone(t *testing.T) {
	down := errors.New("api server down")
	cases := []struct {
		name   string
		inject func(f launchFixture)
	}{
		{"first volume", func(f launchFixture) { f.boot.failAt("CreateVolume", 1, false) }},
		{"first volume lost", func(f launchFixture) { f.boot.failAt("CreateVolume", 1, true) }},
		{"first instance", func(f launchFixture) { f.boot.failAt("CreateInstance", 1, false) }},
		{"first instance lost", func(f launchFixture) { f.boot.failAt("CreateInstance", 1, true) }},
		{"first read", func(f launchFixture) { f.boot.failAt("GetInstance", 1, false) }},
		{"second volume", func(f launchFixture) { f.boot.failAt("CreateVolume", 2, false) }},
		{"second volume lost", func(f launchFixture) { f.boot.failAt("CreateVolume", 2, true) }},
		{"second instance", func(f launchFixture) { f.boot.failAt("CreateInstance", 2, false) }},
		{"second instance lost", func(f launchFixture) { f.boot.failAt("CreateInstance", 2, true) }},
		{"second read", func(f launchFixture) { f.boot.failAt("GetInstance", 2, false) }},
		{"first volume step", func(f launchFixture) { f.store.FailAfter(1, down) }},
		{"first instance step", func(f launchFixture) { f.store.FailAfter(2, down) }},
		{"second volume step", func(f launchFixture) { f.store.FailAfter(3, down) }},
		{"second instance step", func(f launchFixture) { f.store.FailAfter(4, down) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLaunch(t, "undo-"+tc.name)
			tc.inject(f)
			if _, err := f.launch(t, 2); resource.CodeOf(err) != resource.CodeUnavailable {
				t.Fatalf("err %v, want unavailable", err)
			}
			f.assertNothingLeft(t)
			if rec := f.record(t); rec.Phase != launch.Failed || rec.Attempt != 1 {
				t.Fatalf("record %+v want failed", rec)
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
			if rec := f.record(t); rec.Phase != launch.Succeeded || rec.Attempt != 2 {
				t.Fatalf("retried record %+v", rec)
			}
		})
	}
}

// TestUndoDeletesInReverseOrder pins that the undo deletes the last create
// first: the second boot volume, then the first instance, whose boot volume
// compute deletes with it.
func TestUndoDeletesInReverseOrder(t *testing.T) {
	f := newLaunch(t, "undo-order")
	f.boot.failAt("CreateInstance", 2, false)
	if _, err := f.launch(t, 2); err == nil {
		t.Fatal("launch succeeded")
	}
	plan := f.plan(1, 2)
	want := []string{plan[2].Resource, plan[1].Resource}
	f.boot.mu.Lock()
	got := slices.Clone(f.boot.deletes)
	f.boot.mu.Unlock()
	if !slices.Equal(got, want) {
		t.Fatalf("deletes %v want %v", got, want)
	}
}

// TestCutShortUndoIsFinishedByTheRetry pins that an undo whose delete keeps
// failing stays recorded undoing, the retry with the same token finishes the
// undo before it launches again, and nothing of the first attempt is left.
func TestCutShortUndoIsFinishedByTheRetry(t *testing.T) {
	f := newLaunch(t, "undo-cut-short")
	f.boot.failAt("CreateInstance", 1, false)
	f.boot.failFor("DeleteVolume", 1, undoAttempts)
	if _, err := f.launch(t, 1); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("err %v, want unavailable", err)
	}
	if rec := f.record(t); rec.Phase != launch.Undoing {
		t.Fatalf("record %+v want undoing", rec)
	}
	if v, _, _ := f.boot.left(); v != 1 {
		t.Fatalf("volumes %d, want the one the undo could not delete", v)
	}
	if _, err := f.launch(t, 1); err != nil {
		t.Fatal(err)
	}
	if rec := f.record(t); rec.Phase != launch.Succeeded || rec.Attempt != 2 {
		t.Fatalf("record %+v", rec)
	}
	if v, i, ips := f.boot.left(); v != 1 || i != 1 || ips != 1 {
		t.Fatalf("live volumes %d instances %d ips %d want 1 each", v, i, ips)
	}
}

// TestUndoNeedsTheRecord pins that a launch whose undo cannot be recorded
// deletes nothing and stays running, so the retry resumes the same attempt
// with the creates it already made.
func TestUndoNeedsTheRecord(t *testing.T) {
	f := newLaunch(t, "undo-unrecorded")
	f.boot.failAt("CreateInstance", 1, false)
	f.store.FailAfter(2, errors.New("api server down"))
	if _, err := f.launch(t, 1); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("err %v, want unavailable", err)
	}
	if rec := f.record(t); rec.Phase != launch.Running || len(rec.Steps) != 1 {
		t.Fatalf("record %+v want running with the volume", rec)
	}
	if v, _, _ := f.boot.left(); v != 1 {
		t.Fatalf("volumes %d want 1", v)
	}
	if _, err := f.launch(t, 1); err != nil {
		t.Fatal(err)
	}
	if rec := f.record(t); rec.Phase != launch.Succeeded || rec.Attempt != 1 {
		t.Fatalf("record %+v", rec)
	}
	if v, i := f.created(); v != 1 || i != 1 {
		t.Fatalf("made volumes %d instances %d want 1 each", v, i)
	}
}

// heldVolume holds the first CreateVolume of one volume id until release.
type heldVolume struct {
	storagev1.VolumeServiceClient
	id               string
	entered, release chan struct{}
	once             sync.Once
}

func (h *heldVolume) CreateVolume(
	ctx context.Context, req *storagev1.CreateVolumeRequest, opts ...grpc.CallOption,
) (*longrunningpb.Operation, error) {
	if req.GetVolumeId() == h.id {
		h.once.Do(func() {
			close(h.entered)
			<-h.release
		})
	}
	return h.VolumeServiceClient.CreateVolume(ctx, req, opts...)
}

// TestCreateAfterAnUndoIsUndone runs two requests with one token: the first
// is held before its second volume while the second request fails and
// undoes the attempt. The first then creates its volume and instance, finds
// the attempt undone and deletes them, so nothing is left.
func TestCreateAfterAnUndoIsUndone(t *testing.T) {
	f := newLaunch(t, "undo-overlap")
	held := &heldVolume{
		VolumeServiceClient: f.client.volumes, id: bootVolumeID(f.m.Key, 1, 1),
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	f.client.volumes = held
	first := make(chan error, 1)
	go func() {
		_, err := f.launch(t, 2)
		first <- err
	}()
	<-held.entered
	f.boot.failAt("GetInstance", 2, false)
	if _, err := f.launch(t, 2); err == nil {
		t.Fatal("the failing request succeeded")
	}
	if rec := f.record(t); rec.Phase != launch.Failed {
		t.Fatalf("record %+v want failed", rec)
	}
	close(held.release)
	if err := <-first; !errors.Is(err, launch.ErrUndone) {
		t.Fatalf("held request: %v, want undone", err)
	}
	f.assertNothingLeft(t)
}
