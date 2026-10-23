package grpcclient

import (
	"context"
	"testing"
	"time"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestInterruptedOpSaveDoesNotReplayTheOldDetach pins #213 case 3. Detach A
// is accepted and its operation id saved. The volume is attached again, and
// detach B, with the same parameters, drops it, but the write that saves B's
// operation id fails. A retry of B must return B's operation, not A's.
func TestInterruptedOpSaveDoesNotReplayTheOldDetach(t *testing.T) {
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
	world.finishAll()
	setVolumeInstance(world, "", "")
	if vols := world.volumeNames(instanceName(projectID, instID)); len(vols) != 1 {
		t.Fatalf("detach B did not drop the volume: %v", vols)
	}

	again, err := client.DetachVolume(ctx, mutB, req)
	if err != nil {
		t.Fatalf("retry B: %v", err)
	}
	world.mu.Lock()
	rec := world.byRequest[requestUUID(mutB.Key, "detach")]
	world.mu.Unlock()
	if rec == nil {
		t.Fatal("no stored update for detach B")
	}
	opB, err := operationFrom(rec.op, resource.ServiceCompute)
	if err != nil {
		t.Fatal(err)
	}
	if again.Operation.ID == first.Operation.ID || again.Operation.ID != opB.ID {
		t.Fatalf("retry B returned op %s; detach A was %s, detach B is %s",
			again.Operation.ID, first.Operation.ID, opB.ID)
	}
	if again.Items[0].Status != resource.AttachmentDetaching || again.Items[0].Device != "/dev/sdf" {
		t.Fatalf("retry B item %+v", again.Items[0])
	}
}

func setVolumeInstance(world *detachWorld, inst, device string) {
	world.mu.Lock()
	defer world.mu.Unlock()
	world.vol.Status.Instance = inst
	world.vol.Status.DeviceName = device
}

// TestTagWriteKeepsARecordWrittenMeanwhile pins #213 case 1 under a race:
// a detach record written between CreateTags' read and its write makes the
// etag stale, and the reread write keeps that record.
func TestTagWriteKeepsARecordWrittenMeanwhile(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const instID = "i-0123456789abcdef0"
	holder := observedInstance(projectID, instID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY, computev1.InstancePower_INSTANCE_POWER_RUNNING)
	holder.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, "vol-0123456789abcdef0"), DeviceName: "boot", Boot: true},
	}
	// A record within the window, on the wall clock the client prunes with.
	record := map[string]string{
		labelDetachPrefix + "vol-0fedcba9876543210": detachRecordValue(detachRequestHex("k-other"), "/dev/sdf", time.Now()),
	}
	world := &detachWorld{
		inst:      []*computev1.Instance{holder},
		byRequest: map[string]*detachRecord{},
	}
	reads := 0
	world.beforeWrite = func(inst *computev1.Instance) {
		reads++
		labels := map[string]string{}
		for k, v := range inst.GetLabels() {
			labels[k] = v
		}
		for k, v := range record {
			labels[k] = v
		}
		inst.Labels = labels
	}
	client := dialDetachWorld(t, world)
	id, err := resource.Parse[resource.InstanceID](instID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateTags(context.Background(),
		backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-tag", Fingerprint: "fp-tag"},
		resource.CreateTagsRequest{IDs: []resource.InstanceID{id}, Tags: map[string]string{"team": "storage"}},
	); err != nil {
		t.Fatal(err)
	}
	labels := world.labelsOf(instanceName(projectID, instID))
	for k, v := range record {
		if labels[k] != v {
			t.Fatalf("record %s lost: labels %v", k, labels)
		}
	}
	if labels["team"] != "storage" || reads != 1 {
		t.Fatalf("labels %v, concurrent writes %d", labels, reads)
	}
	if vols := world.volumeNames(instanceName(projectID, instID)); len(vols) != 1 {
		t.Fatalf("a labels-only update changed the volumes: %v", vols)
	}
}

// TestDetachOpTokenRules pins what a saved operation id means for a retry.
func TestDetachOpTokenRules(t *testing.T) {
	reqA, reqB := detachRequestHex("k-a"), detachRequestHex("k-b")
	rows := []struct {
		name  string
		rec   detachReplay
		fp    string
		match opMatch
	}{
		{"no saved id", detachReplay{requestHex: reqA}, "fp", opUnknown},
		{
			"this request, same parameters",
			detachReplay{requestHex: reqA, opLocal: "0000000000000001", fingerprint: detachFPToken(reqA, "fp")},
			"fp", opSaved,
		},
		{
			"this request, other parameters",
			detachReplay{requestHex: reqA, opLocal: "0000000000000001", fingerprint: detachFPToken(reqA, "fp")},
			"fp-2", opOtherParams,
		},
		{
			"another request's id next to this record",
			detachReplay{requestHex: reqB, opLocal: "0000000000000001", fingerprint: detachFPToken(reqA, "fp")},
			"fp", opOtherParams,
		},
		{
			"a pre-#213 token, same parameters",
			detachReplay{requestHex: reqA, opLocal: "0000000000000001", fingerprint: legacyFPToken("fp")},
			"fp", opUnknown,
		},
		{
			"a pre-#213 token, other parameters",
			detachReplay{requestHex: reqA, opLocal: "0000000000000001", fingerprint: legacyFPToken("fp")},
			"fp-2", opOtherParams,
		},
	}
	for _, row := range rows {
		if got := row.rec.opMatch(row.fp); got != row.match {
			t.Errorf("%s: got %d, want %d", row.name, got, row.match)
		}
	}
}
