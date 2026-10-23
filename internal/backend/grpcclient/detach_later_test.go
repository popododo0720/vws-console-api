package grpcclient

import (
	"context"
	"testing"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestRetryAfterLaterDetachOfTheVolume pins #353. Detach A is accepted and
// its operation id saved. The volume is attached again, and detach B, with
// another token, drops it. The record of the volume is B's now, but a retry
// of A must still answer A's detach (AGENTS.md: "even after ... a
// reattach"), not IncorrectState for an available volume.
func TestRetryAfterLaterDetachOfTheVolume(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const (
		instID = "i-0123456789abcdef0"
		rootID = "vol-0123456789abcdef0"
		dataID = "vol-0fedcba9876543210"
	)
	ready := commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	holder := observedInstance(projectID, instID, ready, computev1.InstancePower_INSTANCE_POWER_RUNNING)
	holder.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, rootID), DeviceName: "boot", Boot: true},
		{Volume: volumeName(projectID, dataID), DeviceName: "/dev/sdf"},
	}
	dataVol := observedVolume(projectID, dataID, ready, instID)
	dataVol.Status.DeviceName = "/dev/sdf"
	world := &detachWorld{
		inst:      []*computev1.Instance{holder},
		vol:       dataVol,
		byRequest: map[string]*detachRecord{},
	}
	client := dialDetachWorld(t, world)
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	data, err := resource.Parse[resource.VolumeID](dataID)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := resource.Parse[resource.InstanceID](instID)
	if err != nil {
		t.Fatal(err)
	}
	req := resource.DetachVolumeRequest{VolumeID: data, InstanceID: inst, Device: "/dev/sdf"}
	// Identical parameters give identical fingerprints, as in cloud.mutate.
	mutA := backend.Mutation{Scope: scope, Key: "k-a", Fingerprint: "fp-same"}
	mutB := backend.Mutation{Scope: scope, Key: "k-b", Fingerprint: "fp-same"}

	first, err := client.DetachVolume(ctx, mutA, req)
	if err != nil {
		t.Fatal(err)
	}
	world.finishAll()
	setVolumeInstance(world, "", "")
	if _, err := client.AttachVolume(ctx, backend.Mutation{Scope: scope, Key: "k-re", Fingerprint: "fp-re"},
		resource.AttachVolumeRequest{VolumeID: data, InstanceID: inst, Device: "/dev/sdf"}); err != nil {
		t.Fatal(err)
	}
	world.finishAll()
	setVolumeInstance(world, instID, "/dev/sdf")

	world.mu.Lock()
	world.failSameSpec = 1
	world.mu.Unlock()
	if _, err := client.DetachVolume(ctx, mutB, req); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("interrupted detach B: %v", err)
	}
	second, err := client.DetachVolume(ctx, mutB, req)
	if err != nil {
		t.Fatalf("detach B: %v", err)
	}
	world.finishAll()
	setVolumeInstance(world, "", "")
	again, err := client.DetachVolume(ctx, mutA, req)
	if err != nil {
		t.Fatalf("retry A after B: %v", err)
	}
	if again.Operation.ID != first.Operation.ID {
		t.Fatalf("retry A returned op %s, want A's %s", again.Operation.ID, first.Operation.ID)
	}
	retryB, err := client.DetachVolume(ctx, mutB, req)
	if err != nil || retryB.Operation.ID != second.Operation.ID {
		t.Fatalf("retry B op %v err %v, want B's %s", retryB.Operation.ID, err, second.Operation.ID)
	}
}
