package grpcclient

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// upgradeFixtures holds records the previous released build wrote. README.md
// in that directory names the build and the command that produced them.
const upgradeFixtures = "../../../testdata/upgrade/ceaf591"

type upgradeIdempotency struct {
	Account     string                       `json:"account"`
	Subject     string                       `json:"subject"`
	Action      string                       `json:"action"`
	ClientToken string                       `json:"clientToken"`
	Request     resource.DetachVolumeRequest `json:"request"`
	Key         string                       `json:"key"`
	Fingerprint string                       `json:"fingerprint"`
}

type upgradeLabels struct {
	Now    time.Time         `json:"now"`
	Labels map[string]string `json:"labels"`
}

type upgradeMidFlight struct {
	upgradeLabels
	VolumeID string `json:"volumeId"`
}

type upgradeReplay struct {
	VolumeID string `json:"volumeId"`
	OpID     string `json:"opId"`
}

type upgradeBudget struct {
	upgradeLabels
	Replay upgradeReplay `json:"replay"`
}

type upgradeHeld struct {
	upgradeLabels
	HeldVolumeID    string `json:"heldVolumeId"`
	HeldKey         string `json:"heldKey"`
	HeldFingerprint string `json:"heldFingerprint"`
	HeldOpID        string `json:"heldOpId"`
	PendingVolumeID string `json:"pendingVolumeId"`
	PendingOp       string `json:"pendingOp"`
}

func loadUpgrade(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(upgradeFixtures, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// TestPreviousReleaseRecords decodes records the previous released build
// wrote and answers a retry with them the same way that build did. A changed
// label key or record encoding leaves the record undecodable and fails here.
func TestPreviousReleaseRecords(t *testing.T) {
	var idem upgradeIdempotency
	loadUpgrade(t, "idempotency.json", &idem)
	requestHex := detachRequestHex(idem.Key)

	t.Run("mid-flight", func(t *testing.T) {
		var f upgradeMidFlight
		loadUpgrade(t, "detach-mid-flight.json", &f)
		rec, ok := detachReplayFrom(f.Labels, f.VolumeID)
		if !ok {
			t.Fatal("the current code cannot decode the detach record")
		}
		if rec.requestHex != requestHex || rec.device != idem.Request.Device {
			t.Fatalf("record %s %s, want %s %s", rec.requestHex, rec.device, requestHex, idem.Request.Device)
		}
		if rec.opLocal != "" {
			t.Fatalf("mid-flight record has operation id %q", rec.opLocal)
		}
		if got := rec.opMatch(idem.Fingerprint); got != opUnknown {
			t.Fatalf("opMatch = %v, want opUnknown: no id is saved yet", got)
		}
		if got, want := pruneDetachRecords(f.Labels, f.Now), storedDetachRecords(f.Labels); !maps.Equal(got, want) {
			t.Fatalf("pruned mid-flight record:\n got %v\nwant %v", got, want)
		}
	})

	t.Run("op ids near the label budget", func(t *testing.T) {
		var f upgradeBudget
		loadUpgrade(t, "op-labels-budget.json", &f)
		if len(f.Labels) != labelMax-1 {
			t.Fatalf("%d labels, want %d: the fixture sits one label below compute's limit", len(f.Labels), labelMax-1)
		}
		if pending := pendingDetachOps(f.Labels, f.Now); pending != 0 {
			t.Fatalf("%d detach records reserve an operation id; the fixture has every id saved", pending)
		}
		if n := detachRecordsInWindow(f.Labels, f.Now, ""); n != backend.MaxDetachReplays {
			t.Fatalf("%d records within the window, want %d", n, backend.MaxDetachReplays)
		}
		rec, ok := detachReplayFrom(f.Labels, f.Replay.VolumeID)
		if !ok {
			t.Fatal("the current code cannot decode the detach record")
		}
		if rec.requestHex != requestHex || rec.device != idem.Request.Device || rec.opLocal != f.Replay.OpID {
			t.Fatalf("record %+v, want request %s device %s op %s", rec, requestHex, idem.Request.Device, f.Replay.OpID)
		}
		if got := rec.opMatch(idem.Fingerprint); got != opSaved {
			t.Fatalf("opMatch = %v, want opSaved", got)
		}
		account, err := resource.Parse[resource.AccountID](idem.Account)
		if err != nil {
			t.Fatal(err)
		}
		inst, err := resource.Parse[resource.InstanceID](idem.Request.InstanceID.String())
		if err != nil {
			t.Fatal(err)
		}
		vol, err := resource.Parse[resource.VolumeID](f.Replay.VolumeID)
		if err != nil {
			t.Fatal(err)
		}
		rec.instanceID = inst
		acc, err := (computeClient{&api{}}).acceptDetachReplay(
			context.Background(), account, resource.Volume{ID: vol, OwnerID: account}, resource.Instance{ID: inst}, rec,
		)
		if err != nil {
			t.Fatal(err)
		}
		if got := acc.Operation.ID.Local(); got != f.Replay.OpID {
			t.Fatalf("replay gives operation %s, want the saved %s", got, f.Replay.OpID)
		}
		if acc.Operation.Action != resource.ActionDetachVolume {
			t.Fatalf("replay gives action %s", acc.Operation.Action)
		}
		if len(acc.Items) != 1 || acc.Items[0].Device != idem.Request.Device {
			t.Fatalf("replay gives attachments %+v", acc.Items)
		}
	})

	t.Run("held record", func(t *testing.T) {
		var f upgradeHeld
		loadUpgrade(t, "held-record.json", &f)
		if got, want := pruneDetachRecords(f.Labels, f.Now), storedDetachRecords(f.Labels); !maps.Equal(got, want) {
			t.Fatalf("prune dropped a held record:\n got %v\nwant %v", got, want)
		}
		if !detachRecoveryPending(f.Labels, f.Now) {
			t.Fatal("the fixture does not hold a pending recovery")
		}
		if n := pendingDetachOps(f.Labels, f.Now); n != 1 {
			t.Fatalf("%d pending operation ids, want 1", n)
		}
		if n := detachRecordsInWindow(f.Labels, f.Now, ""); n != 1 {
			t.Fatalf("%d records within the window, want 1: the held record is outside it", n)
		}
		rec, ok := detachReplayFrom(f.Labels, f.HeldVolumeID)
		if !ok {
			t.Fatal("the current code cannot decode the held record")
		}
		if rec.requestHex != detachRequestHex(f.HeldKey) || rec.opLocal != f.HeldOpID {
			t.Fatalf("held record %+v, want request %s op %s", rec, detachRequestHex(f.HeldKey), f.HeldOpID)
		}
		if got := rec.opMatch(f.HeldFingerprint); got != opSaved {
			t.Fatalf("opMatch = %v, want opSaved", got)
		}

		saved := maps.Clone(f.Labels)
		saved[labelDetachOpPrefix+f.PendingVolumeID] = f.PendingOp
		after := pruneDetachRecords(saved, f.Now)
		if _, ok := after[labelDetachPrefix+f.HeldVolumeID]; ok {
			t.Fatal("the expired record outlived the pending recovery")
		}
		if _, ok := after[labelDetachPrefix+f.PendingVolumeID]; !ok {
			t.Fatal("prune dropped the record whose id was just saved")
		}
	})
}
