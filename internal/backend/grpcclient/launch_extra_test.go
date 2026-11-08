package grpcclient

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend/launch"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// mixedExtras is a default and a kept extra volume, which a compute with
// vws-compute#173 launches.
func mixedExtras() []resource.LaunchVolume {
	return []resource.LaunchVolume{
		{Device: "/dev/sdf", SizeGiB: 20, Type: resource.VolumeGP3},
		{Device: "/dev/sdg", SizeGiB: 125, Type: resource.VolumeST1, Kept: true},
	}
}

func (f launchFixture) launchExtras(
	t *testing.T, count int, extras []resource.LaunchVolume,
) (resource.Accepted[resource.Instance], error) {
	t.Helper()
	sub, err := resource.Parse[resource.SubnetID]("subnet-01234567")
	if err != nil {
		t.Fatal(err)
	}
	return f.client.RunInstances(context.Background(), f.m, resource.RunInstancesRequest{
		ImageID: mustImage(t, catalogAMI), InstanceType: "vws.small", SubnetID: sub, Count: count,
		ExtraVolumes: extras,
	})
}

func instanceIDs(acc resource.Accepted[resource.Instance]) []resource.InstanceID {
	ids := make([]resource.InstanceID, 0, len(acc.Items))
	for _, inst := range acc.Items {
		ids = append(ids, inst.ID)
	}
	return ids
}

// TestExtraVolumesArePlannedAndCreatedPerIndex pins the gRPC shape of #423
// AC2: each index plans and creates its boot volume, then each extra volume
// in the order sent, then its instance. An extra volume is blank, with the
// mapping's size, type and performance, and its id and request id are
// derived from the key, the attempt, the index and its position, apart from
// the boot volume's. CreateInstance attaches it at the device as sent, with
// delete_on_termination always set, and leaves the boot attachment's unset.
func TestExtraVolumesArePlannedAndCreatedPerIndex(t *testing.T) {
	f := newLaunch(t, "extra-plan")
	f.boot.honorsDeleteOnTermination = true
	extras := mixedExtras()
	if _, err := f.launchExtras(t, 2, extras); err != nil {
		t.Fatal(err)
	}
	projectID := project(f.m.Account)
	rec := f.record(t)
	var want []launch.Step
	for i := range 2 {
		want = append(want, launch.Step{
			Kind: launch.StepVolume, Index: i, Resource: volumeName(projectID, bootVolumeID(f.m.Key, 1, i)),
		})
		for j := range extras {
			want = append(want, launch.Step{
				Kind: launch.StepVolume, Index: i, Resource: volumeName(projectID, extraVolumeID(f.m.Key, 1, i, j)),
			})
		}
		want = append(want, launch.Step{
			Kind: launch.StepInstance, Index: i, Resource: instanceName(projectID, launchInstanceID(f.m.Key, 1, i)),
		})
	}
	if !slices.Equal(rec.Plan, want) || !slices.Equal(rec.Steps, want) {
		t.Fatalf("plan %v\nsteps %v\nwant %v", rec.Plan, rec.Steps, want)
	}
	if got := launchExtras(rec); got != len(extras) {
		t.Fatalf("the record reads %d extra volumes, want %d", got, len(extras))
	}
	f.boot.mu.Lock()
	sent := slices.Clone(f.boot.sentVolumes)
	attached := f.boot.attached[instanceName(projectID, launchInstanceID(f.m.Key, 1, 1))]
	f.boot.mu.Unlock()
	if len(sent) != 2*(1+len(extras)) {
		t.Fatalf("CreateVolume calls %d", len(sent))
	}
	ids, requests := map[string]bool{}, map[string]bool{}
	for _, req := range sent {
		ids[req.GetVolumeId()], requests[req.GetRequestId()] = true, true
	}
	if len(ids) != len(sent) || len(requests) != len(sent) {
		t.Fatalf("volume ids %v and request ids %v are not distinct", ids, requests)
	}
	for j, extra := range extras {
		req := sent[1+j]
		iops, miBps := extra.Performance()
		spec := req.GetVolume().GetSpec()
		if req.GetVolumeId() != extraVolumeID(f.m.Key, 1, 0, j) ||
			req.GetRequestId() != requestUUID(extraParts(f.m.Key, 1, 0, j)...) ||
			spec.GetSource() != nil || spec.GetSizeGib() != extra.SizeGiB ||
			spec.GetType() != storageType(extra.VolumeType()) || spec.GetIops() != iops ||
			spec.GetThroughputMibps() != miBps || req.GetVolume().GetLabels()[labelFingerprint] != "fp" {
			t.Fatalf("extra %d CreateVolume %v", j, req)
		}
	}
	if len(attached) != 1+len(extras) || attached[0].DeleteOnTermination != nil || !attached[0].GetBoot() {
		t.Fatalf("CreateInstance attachments %v", attached)
	}
	for j, extra := range extras {
		a := attached[1+j]
		if a.GetVolume() != volumeName(projectID, extraVolumeID(f.m.Key, 1, 1, j)) || a.GetDeviceName() != extra.Device ||
			a.GetBoot() || a.DeleteOnTermination == nil || a.GetDeleteOnTermination() == extra.Kept {
			t.Fatalf("extra %d attachment %v, want %+v", j, a, extra)
		}
	}
	if launchPlan(projectID, f.m.Key, 1, 1, 0)[0].Resource != want[0].Resource {
		t.Fatal("a launch without extra volumes names another boot volume")
	}
}

// TestExtraDeleteOnTerminationNeedsAComputeThatHonorsIt pins the #423 AC3
// gate for extra volumes: a compute before vws-compute#173 drops
// delete_on_termination and keeps every volume but the boot one, so a launch
// with a default extra volume is refused as UnsupportedOperation naming the
// field and the device after the read that shows it, and the undo leaves
// nothing. A retry with the token is the next attempt and is refused the
// same way. A launch whose extra volumes are all kept is what that compute
// does, and launches.
func TestExtraDeleteOnTerminationNeedsAComputeThatHonorsIt(t *testing.T) {
	f := newLaunch(t, "extra-before-173")
	for attempt := 1; attempt <= 2; attempt++ {
		_, err := f.launchExtras(t, 1, mixedExtras())
		e := resource.AsError(err)
		if !resource.IsUnsupported(e) ||
			!strings.Contains(e.Message, "Ebs.DeleteOnTermination=true is not supported for /dev/sdf: ") {
			t.Fatalf("attempt %d: err %v, want UnsupportedOperation naming the field and device", attempt, err)
		}
		f.assertNothingLeft(t)
		if rec := f.record(t); rec.Phase != launch.Failed || rec.Attempt != attempt {
			t.Fatalf("attempt %d: record %+v, want failed", attempt, rec)
		}
	}
	kept := newLaunch(t, "extra-kept-before-173")
	acc, err := kept.launchExtras(t, 1, mixedExtras()[1:])
	if err != nil || len(acc.Items) != 1 || len(acc.Items[0].BlockDevices) != 2 {
		t.Fatalf("kept extra: %v %+v", err, acc.Items)
	}
	if block := acc.Items[0].BlockDevices[1]; block.Device != "/dev/sdg" || block.DeleteOnTermination {
		t.Fatalf("kept extra %+v", block)
	}
	if v, i, _ := kept.boot.left(); v != 2 || i != 1 {
		t.Fatalf("kept extra launch left volumes %d instances %d", v, i)
	}
}

// TestExtraVolumeFailureAtEveryStepIsUndone extends #392 to extra volumes: a
// launch of two instances with a default and a kept extra volume that fails
// at any create, any read after one, or any record write of a step leaves
// no volume, instance or private IP, kept volumes included, and is recorded
// failed. A retry launches both, and a second retry returns the same
// instances.
func TestExtraVolumeFailureAtEveryStepIsUndone(t *testing.T) {
	down := errors.New("api server down")
	type inject func(f launchFixture)
	cases := map[string]inject{}
	for n := 1; n <= 6; n++ {
		cases[fmt.Sprintf("volume %d", n)] = func(f launchFixture) { f.boot.failAt("CreateVolume", n, false) }
		cases[fmt.Sprintf("volume %d lost", n)] = func(f launchFixture) { f.boot.failAt("CreateVolume", n, true) }
	}
	for n := 1; n <= 2; n++ {
		cases[fmt.Sprintf("instance %d", n)] = func(f launchFixture) { f.boot.failAt("CreateInstance", n, false) }
		cases[fmt.Sprintf("instance %d lost", n)] = func(f launchFixture) { f.boot.failAt("CreateInstance", n, true) }
		cases[fmt.Sprintf("read %d", n)] = func(f launchFixture) { f.boot.failAt("GetInstance", n, false) }
	}
	for n := 1; n <= 8; n++ {
		cases[fmt.Sprintf("step %d", n)] = func(f launchFixture) { f.store.FailAfter(n, down) }
	}
	for name, inject := range cases {
		t.Run(name, func(t *testing.T) {
			f := newLaunch(t, "extra-undo-"+name)
			f.boot.honorsDeleteOnTermination = true
			inject(f)
			if _, err := f.launchExtras(t, 2, mixedExtras()); resource.CodeOf(err) != resource.CodeUnavailable {
				t.Fatalf("err %v, want unavailable", err)
			}
			f.assertNothingLeft(t)
			if rec := f.record(t); rec.Phase != launch.Failed || rec.Attempt != 1 {
				t.Fatalf("record %+v want failed", rec)
			}
			first, err := f.launchExtras(t, 2, mixedExtras())
			if err != nil {
				t.Fatal(err)
			}
			again, err := f.launchExtras(t, 2, mixedExtras())
			if err != nil || !slices.Equal(instanceIDs(first), instanceIDs(again)) || len(first.Items) != 2 {
				t.Fatalf("retry %v then %v err %v", instanceIDs(first), instanceIDs(again), err)
			}
			if v, i, ips := f.boot.left(); v != 6 || i != 2 || ips != 2 {
				t.Fatalf("live volumes %d instances %d ips %d want 6, 2 and 2", v, i, ips)
			}
			if rec := f.record(t); rec.Phase != launch.Succeeded || rec.Attempt != 2 {
				t.Fatalf("retried record %+v", rec)
			}
		})
	}
}

// TestUndoDeletesExtraVolumesInReverseOrder pins that the undo deletes the
// last create first: the extra volumes last sent first, then the boot
// volume.
func TestUndoDeletesExtraVolumesInReverseOrder(t *testing.T) {
	f := newLaunch(t, "extra-undo-order")
	f.boot.failAt("CreateInstance", 1, false)
	if _, err := f.launchExtras(t, 1, mixedExtras()); err == nil {
		t.Fatal("launch succeeded")
	}
	plan := launchPlan(project(f.m.Account), f.m.Key, 1, 1, 2)
	want := []string{plan[2].Resource, plan[1].Resource, plan[0].Resource}
	f.boot.mu.Lock()
	got := slices.Clone(f.boot.deletes)
	f.boot.mu.Unlock()
	if !slices.Equal(got, want) {
		t.Fatalf("deletes %v want %v", got, want)
	}
}

// TestExtraVolumeCrashAfterEveryStepIsResumedOrSwept extends #392 AC 3 to
// extra volumes: a process killed after any create or record write of a
// two-instance launch with two extra volumes each is resumed by a retry with
// the token, or undone by the sweep once idle, and nothing of an undone
// attempt is left.
func TestExtraVolumeCrashAfterEveryStepIsResumedOrSwept(t *testing.T) {
	type crash func(f launchFixture, p *process)
	cases := map[string]crash{}
	for n := 1; n <= 9; n++ {
		cases[fmt.Sprintf("write %d", n)] = func(_ launchFixture, p *process) { p.dieAfter = n }
	}
	for n := 1; n <= 6; n++ {
		cases[fmt.Sprintf("volume %d", n)] = func(f launchFixture, p *process) { f.boot.crashAt("CreateVolume", n, p.kill) }
	}
	for n := 1; n <= 2; n++ {
		cases[fmt.Sprintf("instance %d", n)] = func(f launchFixture, p *process) {
			f.boot.crashAt("CreateInstance", n, p.kill)
		}
	}
	cases["undoing"] = func(f launchFixture, p *process) {
		f.boot.failAt("CreateInstance", 1, false)
		p.dieAfter = 5
	}
	for name, crash := range cases {
		for _, sweep := range []bool{false, true} {
			name := name + map[bool]string{false: "/retry", true: "/sweep"}[sweep]
			t.Run(name, func(t *testing.T) {
				f := newLaunch(t, "extra-crash-"+name)
				f.boot.honorsDeleteOnTermination = true
				p, dying := f.process(t)
				crash(f, p)
				if _, err := dying.launchExtras(t, 2, mixedExtras()); err == nil {
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
					f.client.launches = launch.NewTracker(f.store, func() time.Time { return time.Now().Add(launchIdle) })
					if n, err := f.client.sweepLaunches(ctx); n != 1 || err != nil {
						t.Fatalf("swept %d launches err %v, want 1", n, err)
					}
					f.assertNothingLeft(t)
				}
				first, err := f.launchExtras(t, 2, mixedExtras())
				if err != nil {
					t.Fatal(err)
				}
				again, err := f.launchExtras(t, 2, mixedExtras())
				if err != nil || !slices.Equal(instanceIDs(first), instanceIDs(again)) || len(first.Items) != 2 {
					t.Fatalf("retry %v then %v err %v", instanceIDs(first), instanceIDs(again), err)
				}
				if v, i, ips := f.boot.left(); v != 6 || i != 2 || ips != 2 {
					t.Fatalf("live volumes %d instances %d ips %d want 6, 2 and 2", v, i, ips)
				}
				if rec := f.record(t); rec.Phase != launch.Succeeded {
					t.Fatalf("retried record %+v", rec)
				}
			})
		}
	}
}

// TestGCRemovesALateExtraVolumeOfAFailedLaunch pins that the launch GC reads
// the extra volumes of a dead attempt from the record: an extra volume and
// instance that a failed launch's creates left after its undo are deleted
// once the launch is idle.
func TestGCRemovesALateExtraVolumeOfAFailedLaunch(t *testing.T) {
	f := newLaunch(t, "extra-gc-failed")
	f.boot.honorsDeleteOnTermination = true
	f.boot.failAt("CreateInstance", 2, false)
	if _, err := f.launchExtras(t, 2, mixedExtras()); err == nil {
		t.Fatal("the failing launch succeeded")
	}
	ctx := context.Background()
	projectID := project(f.m.Account)
	volumes := []string{bootVolumeID(f.m.Key, 1, 1)}
	for j := range mixedExtras() {
		volumes = append(volumes, extraVolumeID(f.m.Key, 1, 1, j))
	}
	var attachments []*computev1.VolumeAttachment
	for j, volID := range volumes {
		if _, err := f.boot.CreateVolume(ctx, &storagev1.CreateVolumeRequest{
			Parent: volumeParent(projectID), VolumeId: volID, RequestId: "late-vol-" + volID,
		}); err != nil {
			t.Fatal(err)
		}
		attachments = append(attachments, &computev1.VolumeAttachment{Volume: volumeName(projectID, volID), Boot: j == 0})
	}
	instID := launchInstanceID(f.m.Key, 1, 1)
	if _, err := f.boot.CreateInstance(ctx, &computev1.CreateInstanceRequest{
		Parent: instanceParent(projectID), InstanceId: instID, RequestId: "late-inst-" + instID,
		Instance: &computev1.Instance{Spec: &computev1.InstanceSpec{Volumes: attachments}},
	}); err != nil {
		t.Fatal(err)
	}
	if v, i, _ := f.boot.left(); v != 3 || i != 1 {
		t.Fatalf("late creates left volumes %d instances %d", v, i)
	}
	f.idle(1)
	if n, err := f.client.collectLaunches(ctx); n != 1 || err != nil {
		t.Fatalf("collected %d err %v want 1", n, err)
	}
	f.assertNothingLeft(t)
	if rec := f.record(t); rec.Phase != launch.Failed || rec.Collected != 1 {
		t.Fatalf("collected record %+v", rec)
	}
}

// TestLargestLaunchWithExtraVolumesIsRecorded is the boundary case: ten
// instances with 26 extra volumes each record the whole plan and every step.
func TestLargestLaunchWithExtraVolumesIsRecorded(t *testing.T) {
	f := newLaunch(t, "extra-largest")
	f.boot.honorsDeleteOnTermination = true
	extras := make([]resource.LaunchVolume, 0, resource.MaxLaunchVolumes-1)
	for j := range resource.MaxLaunchVolumes - 1 {
		extras = append(extras, resource.LaunchVolume{Device: "/dev/xvda" + string(rune('a'+j)), SizeGiB: 1})
	}
	acc, err := f.launchExtras(t, 10, extras)
	if err != nil || len(acc.Items) != 10 || len(acc.Items[9].BlockDevices) != resource.MaxLaunchVolumes {
		t.Fatalf("largest launch: %v %d", err, len(acc.Items))
	}
	if rec := f.record(t); len(rec.Plan) != 280 || !slices.Equal(rec.Steps, rec.Plan) {
		t.Fatalf("plan %d steps %d want 280", len(rec.Plan), len(rec.Steps))
	}
}
