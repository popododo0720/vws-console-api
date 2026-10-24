package grpcclient

import (
	"context"
	"testing"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestRecoveryRefusesOtherParameters pins the #362 review. The detach is
// applied but its operation id save fails, and a CreateTags changes the
// instance. A retry with the same token and other parameters is
// IdempotentParameterMismatch (EC2 client-token rules), and it must not
// take the recovery: a later retry with the original parameters still gets
// the detach, and a retry after that the same operation.
func TestRecoveryRefusesOtherParameters(t *testing.T) {
	world, client, _, vols, inst := capacityWorld(t, 1)
	scope := backend.Scope{Account: mustAccount(t)}
	ctx := context.Background()
	m := backend.Mutation{Scope: scope, Key: "k-b", Fingerprint: "fp-b"}
	req := resource.DetachVolumeRequest{VolumeID: vols[0], InstanceID: inst}
	world.mu.Lock()
	world.failSameSpec = 1 // the write that saves the operation id fails
	world.mu.Unlock()
	if _, err := client.DetachVolume(ctx, m, req); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("interrupted: %v", err)
	}
	if _, err := client.CreateTags(ctx, backend.Mutation{Scope: scope, Key: "k-t", Fingerprint: "fp-t"},
		resource.CreateTagsRequest{IDs: []resource.InstanceID{inst}, Tags: map[string]string{"env": "dev"}}); err != nil {
		t.Fatalf("tag: %v", err)
	}
	other := m
	other.Fingerprint = "fp-other"
	if _, err := client.DetachVolume(ctx, other, req); resource.CodeOf(err) != resource.CodeOf(resource.IdempotencyMismatch()) {
		t.Fatalf("other parameters: err %v, want IdempotencyMismatch", err)
	}
	got, err := client.DetachVolume(ctx, m, req)
	if err != nil {
		t.Fatalf("original parameters after the refused retry: %v", err)
	}
	again, err := client.DetachVolume(ctx, m, req)
	if err != nil || again.Operation.ID != got.Operation.ID {
		t.Fatalf("retry op %v err %v, want the recovery's %s", again.Operation.ID, err, got.Operation.ID)
	}
	if _, err := client.DetachVolume(ctx, other, req); resource.CodeOf(err) != resource.CodeOf(resource.IdempotencyMismatch()) {
		t.Fatalf("other parameters after the recovery: err %v, want IdempotencyMismatch", err)
	}
}

// TestRecoveryAfterReattachAndLaterDetach pins the #362 review on top of
// #353. Detach A is applied but its operation id save fails. The volume is
// attached again and detach B, with another token, drops it, so A's record
// moves to its archive slot. A's retry cannot be replayed by compute (the
// instance changed): the recovery finds A's record in the slot and saves an
// operation there, and B's retry still answers B.
func TestRecoveryAfterReattachAndLaterDetach(t *testing.T) {
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
	world := &detachWorld{inst: []*computev1.Instance{holder}, vol: dataVol, byRequest: map[string]*detachRecord{}}
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
	mutA := backend.Mutation{Scope: scope, Key: "k-a", Fingerprint: "fp-same"}
	mutB := backend.Mutation{Scope: scope, Key: "k-b", Fingerprint: "fp-same"}

	world.mu.Lock()
	world.failSameSpec = 1
	world.mu.Unlock()
	if _, err := client.DetachVolume(ctx, mutA, req); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("interrupted detach A: %v", err)
	}
	world.finishAll()
	setVolumeInstance(world, "", "")
	if _, err := client.AttachVolume(ctx, backend.Mutation{Scope: scope, Key: "k-re", Fingerprint: "fp-re"},
		resource.AttachVolumeRequest{VolumeID: data, InstanceID: inst, Device: "/dev/sdf"}); err != nil {
		t.Fatal(err)
	}
	world.finishAll()
	setVolumeInstance(world, instID, "/dev/sdf")
	second, err := client.DetachVolume(ctx, mutB, req)
	if err != nil {
		t.Fatalf("detach B: %v", err)
	}
	world.finishAll()
	setVolumeInstance(world, "", "")

	got, err := client.DetachVolume(ctx, mutA, req)
	if err != nil {
		t.Fatalf("retry A after B: %v", err)
	}
	if got.Operation.ID == second.Operation.ID {
		t.Fatalf("retry A returned B's op %s", got.Operation.ID)
	}
	again, err := client.DetachVolume(ctx, mutA, req)
	if err != nil || again.Operation.ID != got.Operation.ID {
		t.Fatalf("second retry A op %v err %v, want %s", again.Operation.ID, err, got.Operation.ID)
	}
	retryB, err := client.DetachVolume(ctx, mutB, req)
	if err != nil || retryB.Operation.ID != second.Operation.ID {
		t.Fatalf("retry B op %v err %v, want B's %s", retryB.Operation.ID, err, second.Operation.ID)
	}
}
