package grpcclient

import (
	"context"
	"maps"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// A detach record whose device name leaves no room for a stamp in a 63-byte
// label value next to the request id was kept unstamped, so it never expired
// and held two labels for good (#329). Every record is now stamped, the
// request id packed when the device needs the room, so it expires like any
// other: its retry within the window replays it, and the first write past
// the window drops it.
func TestDetachRecordWithALongDeviceExpires(t *testing.T) {
	for _, n := range []int{24, 30, 33} {
		device := "/dev/" + strings.Repeat("x", n-len("/dev/"))
		t.Run(device, func(t *testing.T) { longDeviceRecordExpires(t, device) })
	}
}

func longDeviceRecordExpires(t *testing.T, device string) {
	world, client, name, vols, inst := capacityWorld(t, 1)
	world.mu.Lock()
	world.inst[0].Spec.Volumes[1].DeviceName = device
	world.mu.Unlock()
	start := time.Unix(1_700_000_000, 0).UTC()
	var offset atomic.Int64
	client.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
	scope := backend.Scope{Account: mustAccount(t)}
	ctx := context.Background()
	m := backend.Mutation{Scope: scope, Key: "k-long", Fingerprint: "fp-long"}
	req := resource.DetachVolumeRequest{VolumeID: vols[0], InstanceID: inst}
	first, err := client.DetachVolume(ctx, m, req)
	if err != nil {
		t.Fatalf("detach: %v", err)
	}
	recordKey := labelDetachPrefix + vols[0].String()
	value := world.labelsOf(name)[recordKey]
	if len(value) > labelValueMax {
		t.Fatalf("record %q is %d bytes, over %d", value, len(value), labelValueMax)
	}
	requestHex, got, at, stamped, ok := parseDetachRecord(value)
	if !ok || !stamped || got != device || requestHex != detachRequestHex(m.Key) || !at.Equal(start) {
		t.Fatalf("record %q reads as (%q %q %v stamped=%v ok=%v); want this request, its device and a stamp",
			value, requestHex, got, at, stamped, ok)
	}

	offset.Store(int64(backend.ClientTokenWindow))
	again, err := client.DetachVolume(ctx, m, req)
	if err != nil || again.Operation.ID != first.Operation.ID || again.Items[0].Device != device {
		t.Fatalf("retry within the window: %+v, %v; want op %s on %s", again, err, first.Operation.ID, device)
	}

	offset.Store(int64(backend.ClientTokenWindow + backend.ClientTokenGrace + time.Second))
	if err := tagEnvProd(ctx, client, scope, inst, "k-tag-after"); err != nil {
		t.Fatalf("tag write past the window: %v", err)
	}
	labels := world.labelsOf(name)
	for _, key := range []string{recordKey, labelDetachOpPrefix + vols[0].String()} {
		if v, ok := labels[key]; ok {
			t.Errorf("%s=%q outlived its window", key, v)
		}
	}
}

// A record written unstamped before #329 (a device over 23 bytes) is stamped
// by the first write that sees it, so its window starts there, and during a
// hold it ends with the first expired stamped record, as a record written
// before #303 does (#322).
func TestUnstampedLongDeviceRecordIsBounded(t *testing.T) {
	const grace = backend.ClientTokenGrace
	now := time.Unix(1_700_000_000, 0).UTC()
	req := strings.Repeat("ab", 16)
	longDevice := "/dev/" + strings.Repeat("x", 20) // 25 bytes
	legacy := map[string]string{
		labelDetachPrefix + "vol-g":   req + " " + longDevice,
		labelDetachOpPrefix + "vol-g": "0000000000000007 0123456789abcdef",
	}
	got := pruneDetachRecords(legacy, now)
	requestHex, device, at, stamped, ok := parseDetachRecord(got[labelDetachPrefix+"vol-g"])
	if !ok || !stamped || !at.Equal(now) || requestHex != req || device != longDevice {
		t.Fatalf("legacy record after a write: %v; want it stamped now", got)
	}
	if later := pruneDetachRecords(got, now.Add(backend.ClientTokenWindow+grace+time.Second)); len(later) != 0 {
		t.Fatalf("legacy record past its window: %v, want none", later)
	}

	// Pending (no operation id) during a hold: kept as stored until a stamped
	// record has expired, then stamped like any other.
	held := map[string]string{
		labelDetachPrefix + "vol-g":   req + " " + longDevice,
		labelDetachPrefix + "vol-a":   req + " /dev/sdg " + stampOf(now.Add(-time.Hour)),
		labelDetachOpPrefix + "vol-a": "0000000000000001 0123456789abcdef",
	}
	if got := pruneDetachRecords(held, now); !maps.Equal(got, held) {
		t.Fatalf("records during the hold:\n got %v\nwant %v", got, held)
	}
	expired := maps.Clone(held)
	past := now.Add(-backend.ClientTokenWindow - grace - time.Second)
	expired[labelDetachPrefix+"vol-a"] = req + " /dev/sdg " + stampOf(past)
	if detachRecoveryPending(expired, now) {
		t.Fatal("an unstamped long-device record still holds after a stamped record expired")
	}
	got = pruneDetachRecords(expired, now)
	if _, _, _, stamped, ok := parseDetachRecord(got[labelDetachPrefix+"vol-g"]); !ok || !stamped || len(got) != 1 {
		t.Fatalf("records once a stamped record expired: %v; want only vol-g, stamped", got)
	}
}
