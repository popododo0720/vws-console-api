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

// TestVolumeOnlyRetryOfAnUnsavedDetachAfterAMove pins the never-saved branch
// of #307 (#449). A volume-only detach from instance A is applied, but the
// write that saves its operation id fails. The volume is then attached to B.
// A retry with other parameters is IdempotentParameterMismatch. A retry with
// the same parameters resends the original update to A by its request id and
// returns that operation; B keeps the volume, and the next retry replays the
// id the resend saved.
func TestVolumeOnlyRetryOfAnUnsavedDetachAfterAMove(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const (
		fromID = "i-0123456789abcdef0"
		toID   = "i-0fedcba9876543210"
		dataID = "vol-0fedcba9876543210"
	)
	ready := commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	running := computev1.InstancePower_INSTANCE_POWER_RUNNING
	from := observedInstance(projectID, fromID, ready, running)
	from.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, "vol-0123456789abcdef0"), DeviceName: "boot", Boot: true},
		{Volume: volumeName(projectID, dataID), DeviceName: "/dev/sdf"},
	}
	to := observedInstance(projectID, toID, ready, running)
	to.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, "vol-0abcdef0123456789"), DeviceName: "boot", Boot: true},
	}
	dataVol := observedVolume(projectID, dataID, ready, fromID)
	dataVol.Status.DeviceName = "/dev/sdf"
	world := &detachWorld{
		inst:      []*computev1.Instance{from, to},
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
	fromInst, err := resource.Parse[resource.InstanceID](fromID)
	if err != nil {
		t.Fatal(err)
	}
	toInst, err := resource.Parse[resource.InstanceID](toID)
	if err != nil {
		t.Fatal(err)
	}
	m := backend.Mutation{Scope: scope, Key: "k-moved", Fingerprint: "fp-moved"}
	req := resource.DetachVolumeRequest{VolumeID: data}

	world.mu.Lock()
	world.failSameSpec = 1 // the write that saves the operation id fails
	world.mu.Unlock()
	if _, err := client.DetachVolume(ctx, m, req); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("interrupted detach: %v", err)
	}
	world.finishAll()
	setVolumeInstance(world, "", "")
	world.mu.Lock()
	original := world.byRequest[requestUUID(m.Key, "detach")]
	world.mu.Unlock()
	if original == nil {
		t.Fatal("no stored update for the detach")
	}
	want, err := operationFrom(original.op, resource.ServiceCompute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachVolume(ctx, backend.Mutation{Scope: scope, Key: "k-to", Fingerprint: "fp-to"},
		resource.AttachVolumeRequest{VolumeID: data, InstanceID: toInst, Device: "/dev/sdf"}); err != nil {
		t.Fatal(err)
	}
	world.finishAll()
	setVolumeInstance(world, toID, "/dev/sdf")
	onTo := func(t *testing.T, when string) {
		t.Helper()
		if !slices.Contains(world.volumeNames(instanceName(projectID, toID)), volumeName(projectID, dataID)) {
			t.Fatalf("%s: the retry detached the volume from %s", when, toID)
		}
		if slices.Contains(world.volumeNames(instanceName(projectID, fromID)), volumeName(projectID, dataID)) {
			t.Fatalf("%s: the volume is back on %s", when, fromID)
		}
	}

	other := m
	other.Fingerprint = "fp-moved-other"
	updates := world.updateCount()
	if _, err := client.DetachVolume(ctx, other, req); resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
		t.Fatalf("same token, other parameters: %v", err)
	}
	if n := world.updateCount() - updates; n != 0 {
		t.Fatalf("the mismatched retry wrote to compute %d times", n)
	}
	onTo(t, "other parameters")

	got, err := client.DetachVolume(ctx, m, req)
	if err != nil {
		t.Fatalf("retry after the move: %v", err)
	}
	if got.Operation.ID != want.ID {
		t.Fatalf("retry gave op %s, want the original detach %s", got.Operation.ID, want.ID)
	}
	if item := got.Items[0]; item.InstanceID != fromInst || item.Device != "/dev/sdf" ||
		item.Status != resource.AttachmentDetaching {
		t.Fatalf("retry item %+v, want detaching from %s at /dev/sdf", item, fromID)
	}
	onTo(t, "same parameters")

	again, err := client.DetachVolume(ctx, m, req)
	if err != nil || again.Operation.ID != want.ID {
		t.Fatalf("second retry op %v err %v, want %s", again.Operation.ID, err, want.ID)
	}
	onTo(t, "second retry")
}
