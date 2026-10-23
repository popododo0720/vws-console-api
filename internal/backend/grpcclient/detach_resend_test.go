package grpcclient

import (
	"context"
	"slices"
	"testing"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestRecoveryAfterTagChange pins #352. The detach is applied but the write
// that saves its operation id fails. A CreateTags changes the instance, so
// the resend of the original update no longer matches it byte for byte.
// The retry must still answer the detach, and a later retry the same one.
func TestRecoveryAfterTagChange(t *testing.T) {
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
	got, err := client.DetachVolume(ctx, m, req)
	if err != nil {
		t.Fatalf("recovery after a tag change: %v", err)
	}
	if got.Items[0].InstanceID != inst || got.Items[0].Status != resource.AttachmentDetaching {
		t.Fatalf("recovery %+v", got.Items[0])
	}
	again, err := client.DetachVolume(ctx, m, req)
	if err != nil {
		t.Fatalf("retry after recovery: %v", err)
	}
	if again.Operation.ID != got.Operation.ID {
		t.Fatalf("retry op %s, recovery op %s", again.Operation.ID, got.Operation.ID)
	}
}

// TestRetryAfterReattachWithUnsavedOp pins the bound case of #352. The
// detach is applied but its operation id save fails, the volume is attached
// again, and a CreateTags changes the instance. The retry finds the volume
// bound and this request's record, so its drop write reuses the request id
// for another payload. The detach already happened: the retry answers it
// and does not detach again.
func TestRetryAfterReattachWithUnsavedOp(t *testing.T) {
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
	req := resource.DetachVolumeRequest{VolumeID: data, InstanceID: inst}
	m := backend.Mutation{Scope: scope, Key: "k-a", Fingerprint: "fp-a"}
	world.mu.Lock()
	world.failSameSpec = 1 // the write that saves the operation id fails
	world.mu.Unlock()
	if _, err := client.DetachVolume(ctx, m, req); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("interrupted: %v", err)
	}
	world.finishAll()
	setVolumeInstance(world, "", "")
	if _, err := client.AttachVolume(ctx, backend.Mutation{Scope: scope, Key: "k-re", Fingerprint: "fp-re"},
		resource.AttachVolumeRequest{VolumeID: data, InstanceID: inst, Device: "/dev/sdf"}); err != nil {
		t.Fatal(err)
	}
	world.finishAll()
	setVolumeInstance(world, instID, "/dev/sdf")
	if _, err := client.CreateTags(ctx, backend.Mutation{Scope: scope, Key: "k-t", Fingerprint: "fp-t"},
		resource.CreateTagsRequest{IDs: []resource.InstanceID{inst}, Tags: map[string]string{"env": "dev"}}); err != nil {
		t.Fatalf("tag: %v", err)
	}
	got, err := client.DetachVolume(ctx, m, req)
	if err != nil {
		t.Fatalf("retry after a reattach: %v", err)
	}
	if !slices.Contains(world.volumeNames(instanceName(projectID, instID)), volumeName(projectID, dataID)) {
		t.Fatal("the retry detached again")
	}
	again, err := client.DetachVolume(ctx, m, req)
	if err != nil || again.Operation.ID != got.Operation.ID {
		t.Fatalf("second retry op %v err %v, first retry op %s", again.Operation.ID, err, got.Operation.ID)
	}
}
