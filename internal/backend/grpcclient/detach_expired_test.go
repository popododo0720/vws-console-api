package grpcclient

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// afterDetach is where the volume is when a detach whose operation id was
// never saved is retried.
type afterDetach int

const (
	reattachedHere afterDetach = iota // attached again to the same instance
	movedElsewhere                    // attached to another instance
)

const otherInstID = "i-0fedcba9876543210"

// expiredWorld is capacityWorld with a second running instance, a detach
// of the data volume from the first whose operation id save failed, and
// the volume then attached again where the case says.
func expiredWorld(t *testing.T, after afterDetach, named bool, now *time.Time) (
	*detachWorld, computeClient, backend.Mutation, resource.DetachVolumeRequest, string, string,
) {
	t.Helper()
	world, client, name, vols, inst := capacityWorld(t, 1)
	client.now = func() time.Time { return *now }
	account := mustAccount(t)
	projectID := project(account)
	other := observedInstance(projectID, otherInstID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY, computev1.InstancePower_INSTANCE_POWER_RUNNING)
	other.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, "vol-0aaaaaaaaaaaaaaa0"), DeviceName: "boot", Boot: true},
	}
	world.mu.Lock()
	world.inst = append(world.inst, other)
	world.failSameSpec = 1 // the write that saves the operation id fails
	world.mu.Unlock()

	ctx := context.Background()
	scope := backend.Scope{Account: account}
	m := backend.Mutation{Scope: scope, Key: "k-305-moved", Fingerprint: "fp-305-moved"}
	req := resource.DetachVolumeRequest{VolumeID: vols[0], InstanceID: inst}
	if _, err := client.DetachVolume(ctx, m, req); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("interrupted detach: %v", err)
	}
	world.finishAll()
	setVolumeInstance(world, "", "")

	target, targetName := inst, name
	if after == movedElsewhere {
		parsed, err := resource.Parse[resource.InstanceID](otherInstID)
		if err != nil {
			t.Fatal(err)
		}
		target, targetName = parsed, instanceName(projectID, otherInstID)
	}
	if _, err := client.AttachVolume(ctx, backend.Mutation{Scope: scope, Key: "k-re", Fingerprint: "fp-re"},
		resource.AttachVolumeRequest{VolumeID: vols[0], InstanceID: target, Device: "/dev/sdg"}); err != nil {
		t.Fatalf("attach again: %v", err)
	}
	world.finishAll()
	setVolumeInstance(world, target.String(), "/dev/sdg")
	if !named {
		req.InstanceID = resource.InstanceID{}
	}
	return world, client, m, req, targetName, volumeName(projectID, vols[0].String())
}

// forgetOperationIDs makes the record again one whose operation id was
// never saved, and makes compute forget every request id, as it does past
// backend.ClientTokenWindow.
func forgetOperationIDs(world *detachWorld, volID resource.VolumeID) {
	world.mu.Lock()
	defer world.mu.Unlock()
	for _, item := range world.inst {
		delete(item.Labels, labelDetachOpPrefix+volID.String())
	}
	world.byRequest = map[string]*detachRecord{}
}

// TestRetryPastTheWindowAfterReattachOrMoveIsRefused pins the lead's
// option B on #305 AC2. A detach is applied, its operation id save fails,
// and the volume is attached again: to the same instance, or to another
// one (the volume-only #307 path). Past compute's request id window, while
// the detach record lingers, the retry must not write to compute: a write
// would detach the new attachment or return a new update as the detach. It
// answers IncorrectState with resource.DetachTokenExpiredMessage. Within
// the window the retry still answers the detach without detaching again.
func TestRetryPastTheWindowAfterReattachOrMoveIsRefused(t *testing.T) {
	start := time.Unix(1_700_000_000, 0).UTC()
	for _, tc := range []struct {
		name  string
		after afterDetach
		named bool
	}{
		{"reattached, instance named", reattachedHere, true},
		{"reattached, volume only", reattachedHere, false},
		{"moved, volume only", movedElsewhere, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := start
			world, client, m, req, holder, volName := expiredWorld(t, tc.after, tc.named, &now)
			ctx := context.Background()

			now = start.Add(backend.ClientTokenWindow - 2*backend.ClientTokenGrace)
			if _, err := client.DetachVolume(ctx, m, req); err != nil {
				t.Fatalf("retry within the window: %v", err)
			}
			if !slices.Contains(world.volumeNames(holder), volName) {
				t.Fatal("the retry within the window detached the new attachment")
			}

			forgetOperationIDs(world, req.VolumeID)
			world.mu.Lock()
			updates := world.updates
			world.mu.Unlock()
			for _, past := range []time.Duration{
				backend.ClientTokenWindow - backend.ClientTokenGrace,
				backend.ClientTokenWindow + time.Second,
			} {
				now = start.Add(past)
				_, err := client.DetachVolume(ctx, m, req)
				world.mu.Lock()
				wrote := world.updates - updates
				world.mu.Unlock()
				if wrote != 0 {
					t.Fatalf("retry %s after the detach wrote to compute %d times", past, wrote)
				}
				var rerr *resource.Error
				if !errors.As(err, &rerr) || rerr.Code != resource.CodeConflict ||
					rerr.Kind != resource.KindVolume || rerr.Message != resource.DetachTokenExpiredMessage {
					t.Fatalf("retry %s after the detach: %v, want IncorrectState %q",
						past, err, resource.DetachTokenExpiredMessage)
				}
			}
			if !slices.Contains(world.volumeNames(holder), volName) {
				t.Fatal("the retry past the window detached the new attachment")
			}
		})
	}
}

// A retry that names the instance the volume moved away from finds no
// attachment there and writes nothing, past the window as within it.
func TestRetryPastTheWindowNamingTheOldInstanceWritesNothing(t *testing.T) {
	start := time.Unix(1_700_000_000, 0).UTC()
	now := start
	world, client, m, req, holder, volName := expiredWorld(t, movedElsewhere, true, &now)
	forgetOperationIDs(world, req.VolumeID)
	world.mu.Lock()
	updates := world.updates
	world.mu.Unlock()
	now = start.Add(backend.ClientTokenWindow + time.Second)
	_, err := client.DetachVolume(context.Background(), m, req)
	world.mu.Lock()
	wrote := world.updates - updates
	world.mu.Unlock()
	if wrote != 0 {
		t.Fatalf("retry wrote to compute %d times", wrote)
	}
	var rerr *resource.Error
	if !errors.As(err, &rerr) || !resource.IsAttachmentNotFound(rerr) {
		t.Fatalf("retry naming the old instance: %v, want InvalidAttachment.NotFound", err)
	}
	if !slices.Contains(world.volumeNames(holder), volName) {
		t.Fatal("the retry detached the new attachment")
	}
}

// A record with no stamp (written before #303, or before #329 with a long
// device name) has an unknown age, so past the window by the clock its
// retry still goes to compute by request id, which today's compute still
// remembers, and is not refused (#305).
func TestUnstampedRecordKeepsTheResend(t *testing.T) {
	start := time.Unix(1_700_000_000, 0).UTC()
	for _, tc := range []struct {
		name  string
		after afterDetach
		named bool
	}{
		{"reattached, instance named", reattachedHere, true},
		{"reattached, volume only", reattachedHere, false},
		{"moved, volume only", movedElsewhere, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := start
			world, client, m, req, holder, volName := expiredWorld(t, tc.after, tc.named, &now)
			recordKey := labelDetachPrefix + req.VolumeID.String()
			world.mu.Lock()
			unstamped := false
			for _, item := range world.inst {
				raw, ok := item.Labels[recordKey]
				if !ok {
					continue
				}
				requestHex, device, _, stamped, ok := parseDetachRecord(raw)
				if !ok || !stamped {
					world.mu.Unlock()
					t.Fatalf("record %q, want a stamped record to rewrite", raw)
				}
				item.Labels[recordKey] = requestHex + " " + device
				unstamped = true
			}
			world.mu.Unlock()
			if !unstamped {
				t.Fatal("no detach record to rewrite")
			}

			now = start.Add(backend.ClientTokenWindow + time.Hour)
			_, err := client.DetachVolume(context.Background(), m, req)
			var rerr *resource.Error
			if errors.As(err, &rerr) && rerr.Message == resource.DetachTokenExpiredMessage {
				t.Fatalf("unstamped record refused as expired: %v", err)
			}
			if err != nil {
				t.Fatalf("retry of an unstamped record: %v", err)
			}
			if !slices.Contains(world.volumeNames(holder), volName) {
				t.Fatal("the retry detached the new attachment")
			}
		})
	}
}
