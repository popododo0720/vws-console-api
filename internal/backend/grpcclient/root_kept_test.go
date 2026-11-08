package grpcclient

import (
	"context"
	"strings"
	"testing"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/launch"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (f launchFixture) launchKept(t *testing.T) (resource.Accepted[resource.Instance], error) {
	t.Helper()
	sub, err := resource.Parse[resource.SubnetID]("subnet-01234567")
	if err != nil {
		t.Fatal(err)
	}
	return f.client.RunInstances(context.Background(), f.m, resource.RunInstancesRequest{
		ImageID: mustImage(t, catalogAMI), InstanceType: "vws.small", SubnetID: sub, Count: 1, RootVolumeKept: true,
	})
}

// sent is the boot attachment delete_on_termination of every CreateInstance.
func (f launchFixture) sent() []*bool {
	f.boot.mu.Lock()
	defer f.boot.mu.Unlock()
	return append([]*bool(nil), f.boot.sentDeleteOnTermination...)
}

// TestKeptRootNeedsAComputeThatKeepsIt pins the #423 AC3 gate: a compute
// before vws-compute#173 drops delete_on_termination and deletes the boot
// volume with its instance, so a launch that keeps its root is refused as
// UnsupportedOperation after the read that shows the field was dropped, and
// the undo leaves nothing. A retry with the token is the next attempt and
// is refused the same way.
func TestKeptRootNeedsAComputeThatKeepsIt(t *testing.T) {
	f := newLaunch(t, "kept-before-173")
	for attempt := 1; attempt <= 2; attempt++ {
		_, err := f.launchKept(t)
		e := resource.AsError(err)
		if !resource.IsUnsupported(e) || !strings.Contains(e.Message, "Ebs.DeleteOnTermination=false is not supported: ") {
			t.Fatalf("attempt %d: err %v, want UnsupportedOperation naming the field", attempt, err)
		}
		f.assertNothingLeft(t)
		if rec := f.record(t); rec.Phase != launch.Failed || rec.Attempt != attempt {
			t.Fatalf("attempt %d: record %+v, want failed", attempt, rec)
		}
	}
	for i, got := range f.sent() {
		if got == nil || *got {
			t.Fatalf("CreateInstance %d sent delete_on_termination %v, want false", i, got)
		}
	}
}

// TestDefaultRootLeavesDeleteOnTerminationUnset pins that a launch with the
// EC2 default sends the CreateInstance body it sent before #423 AC3, so a
// launch begun by the previous release replays under its request id; unset
// is true for a boot volume (instance.proto).
func TestDefaultRootLeavesDeleteOnTerminationUnset(t *testing.T) {
	f := newLaunch(t, "default-root")
	if err := f.run(t, 1); err != nil {
		t.Fatal(err)
	}
	if got := f.sent(); len(got) != 1 || got[0] != nil {
		t.Fatalf("CreateInstance sent delete_on_termination %v, want it unset", got)
	}
}

// TestKeptRootLaunchIsResumedByTheRetry pins a kept root across a crash: a
// process killed after CreateInstance leaves the launch running, and the
// retry with the token resumes it with the same request ids and the flag,
// so the instance keeps its root.
func TestKeptRootLaunchIsResumedByTheRetry(t *testing.T) {
	f := newLaunch(t, "kept-resume")
	f.boot.keepsRoots = true
	p, dying := f.process(t)
	f.boot.crashAt("CreateInstance", 1, p.kill)
	if _, err := dying.launchKept(t); err == nil {
		t.Fatal("the killed launch succeeded")
	}
	acc, err := f.launchKept(t)
	if err != nil || len(acc.Items) != 1 || len(acc.Items[0].BlockDevices) != 1 {
		t.Fatalf("resume: %v %+v", err, acc.Items)
	}
	if block := acc.Items[0].BlockDevices[0]; block.Device != resource.RootDeviceName || block.DeleteOnTermination {
		t.Fatalf("resumed root %+v, want kept", block)
	}
	if rec := f.record(t); rec.Phase != launch.Succeeded || rec.Attempt != 1 {
		t.Fatalf("record %+v, want the first attempt succeeded", rec)
	}
	if v, i := f.created(); v != 1 || i != 1 {
		t.Fatalf("created %d volumes and %d instances, want one of each", v, i)
	}
	sent := f.sent()
	if len(sent) != 2 {
		t.Fatalf("CreateInstance calls %d, want the crashed one and its replay", len(sent))
	}
	for i, got := range sent {
		if got == nil || *got {
			t.Fatalf("CreateInstance %d sent delete_on_termination %v, want false", i, got)
		}
	}
}

// TestKeptRootIsUndone pins that the undo of a launch whose root compute
// kept still deletes that volume: the instance delete leaves it, and the
// plan's volume step deletes it.
func TestKeptRootIsUndone(t *testing.T) {
	f := newLaunch(t, "kept-undo")
	f.boot.keepsRoots = true
	f.boot.failAt("GetInstance", 1, false)
	if _, err := f.launchKept(t); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("err %v, want unavailable", err)
	}
	f.assertNothingLeft(t)
	if rec := f.record(t); rec.Phase != launch.Failed {
		t.Fatalf("record %+v, want failed", rec)
	}
}

// TestRootVolumeReadsComputesDeleteOnTermination pins how DescribeVolumes
// reads a root volume over gRPC. Its attachment's DeleteOnTermination is
// the one on the compute spec, unset meaning true for a boot volume. The
// vws-instance label names the instance the volume was made for, not one
// that holds it, so a kept root whose instance is gone or terminated, which
// storage reports on no instance, is available with no attachment.
func TestRootVolumeReadsComputesDeleteOnTermination(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const instID = "i-0123456789abcdef0"
	const rootID = "vol-0fedcba9876543210"
	ready := commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	running := computev1.InstancePower_INSTANCE_POWER_RUNNING
	holder := func(state commonv1.ReconciliationState, dot *bool) *computev1.Instance {
		inst := observedInstance(projectID, instID, state, running)
		inst.Spec.Volumes = []*computev1.VolumeAttachment{{
			Volume: volumeName(projectID, rootID), DeviceName: "boot", Boot: true, DeleteOnTermination: dot,
		}}
		inst.Status.Volumes = []*computev1.ObservedVolumeAttachment{{
			Volume: volumeName(projectID, rootID), DeviceName: "boot",
			State: computev1.VolumeAttachState_VOLUME_ATTACH_STATE_ATTACHED,
		}}
		return inst
	}
	terminated := holder(commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING, proto.Bool(false))
	terminated.DeleteTime = timestamppb.Now()
	rows := []struct {
		name     string
		inst     []*computev1.Instance
		reported string
		inUse    bool
		dot      bool
	}{
		{name: "compute keeps it", inst: []*computev1.Instance{holder(ready, proto.Bool(false))}, inUse: true},
		{name: "compute deletes it", inst: []*computev1.Instance{holder(ready, proto.Bool(true))}, inUse: true, dot: true},
		{name: "compute leaves it unset", inst: []*computev1.Instance{holder(ready, nil)}, inUse: true, dot: true},
		{
			name: "storage names the instance", inst: []*computev1.Instance{holder(ready, proto.Bool(false))},
			reported: instID, inUse: true,
		},
		{name: "its instance is gone"},
		{name: "its instance is terminated", inst: []*computev1.Instance{terminated}},
	}
	for _, row := range rows {
		for _, listed := range []bool{false, true} {
			name := row.name + ", by id"
			if listed {
				name = row.name + ", listed"
			}
			t.Run(name, func(t *testing.T) {
				root := observedVolume(projectID, rootID, ready, row.reported)
				root.Spec.Source = &storagev1.VolumeSpec_Image{Image: imageName(projectID, "ami-0123456789abcdef0")}
				root.Labels = map[string]string{labelInstance: instID}
				client := dialSpecWorld(t, &specWorld{inst: row.inst, vol: []*storagev1.Volume{root}})
				q := resource.VolumeQuery{Page: resource.PageRequest{Size: 50}}
				if !listed {
					q.IDs = []resource.VolumeID{mustVolume(t, rootID)}
				}
				page, err := client.DescribeVolumes(context.Background(), backend.Scope{Account: account}, q)
				if err != nil || len(page.Items) != 1 {
					t.Fatalf("describe: %v %+v", err, page.Items)
				}
				v := page.Items[0]
				if !row.inUse {
					if v.State != resource.VolumeAvailable || !v.InstanceID.IsZero() || v.Device != "" ||
						v.AttachState != "" || v.DeleteOnTermination {
						t.Fatalf("got %+v, want available with no attachment", v)
					}
					return
				}
				if v.State != resource.VolumeInUse || v.InstanceID.String() != instID ||
					v.Device != resource.RootDeviceName || v.AttachState != resource.AttachmentAttached ||
					v.DeleteOnTermination != row.dot {
					t.Fatalf("got %+v, want in-use on %s at %s, attached, DeleteOnTermination %v",
						v, instID, resource.RootDeviceName, row.dot)
				}
			})
		}
	}
}

// TestKeptRootOfATerminatedInstanceIsNotInUse pins that compute's spec of a
// terminated instance holds no volume on detach, as DescribeVolumes reads
// it: a kept root is available, so DetachVolume is VolumeNotInUse with or
// without the instance named, as on the fake, and writes nothing.
func TestKeptRootOfATerminatedInstanceIsNotInUse(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const instID = "i-0123456789abcdef0"
	const rootID = "vol-0fedcba9876543210"
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "volume only", true: "instance named"}[named], func(t *testing.T) {
			terminated := observedInstance(projectID, instID,
				commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING,
				computev1.InstancePower_INSTANCE_POWER_RUNNING)
			terminated.DeleteTime = timestamppb.Now()
			terminated.Spec.Volumes = []*computev1.VolumeAttachment{{
				Volume: volumeName(projectID, rootID), DeviceName: "boot", Boot: true,
				DeleteOnTermination: proto.Bool(false),
			}}
			root := observedVolume(projectID, rootID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, "")
			root.Spec.Source = &storagev1.VolumeSpec_Image{Image: imageName(projectID, "ami-0123456789abcdef0")}
			root.Labels = map[string]string{labelInstance: instID}
			world := &detachWorld{
				inst: []*computev1.Instance{terminated}, vol: root, byRequest: map[string]*detachRecord{},
			}
			client := dialDetachWorld(t, world)
			req := resource.DetachVolumeRequest{VolumeID: mustVolume(t, rootID)}
			if named {
				id, err := resource.Parse[resource.InstanceID](instID)
				if err != nil {
					t.Fatal(err)
				}
				req.InstanceID = id
			}
			_, err := client.DetachVolume(context.Background(), backend.Mutation{
				Scope: backend.Scope{Account: account}, Key: "k-kept", Fingerprint: "fp-kept",
			}, req)
			if want := resource.VolumeNotInUse(req.VolumeID); resource.CodeOf(err) != resource.CodeOf(want) ||
				resource.AsError(err).Message != resource.AsError(want).Message {
				t.Fatalf("detach: %v, want %v", err, want)
			}
			if world.updateCount() != 0 {
				t.Fatalf("updates %d, want none", world.updateCount())
			}
		})
	}
}
