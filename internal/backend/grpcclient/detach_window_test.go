package grpcclient

import (
	"context"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestDetachWindowOverGRPC runs the #303 record window table over the
// resource API. The client stamps and prunes records on the world's clock.
func TestDetachWindowOverGRPC(t *testing.T) {
	backendtest.DetachWindow(t, func() (backend.Set, func(time.Duration)) {
		start := time.Unix(1_700_000_000, 0).UTC()
		var offset atomic.Int64
		clock := func() time.Time { return start.Add(time.Duration(offset.Load())) }
		world := fake.New(fake.Options{Now: clock, Entropy: &fake.Sequence{}})
		set := dialLoopbackClock(t, world, start, clock)()
		return set, func(d time.Duration) { offset.Add(int64(d)) }
	})
}

func stampOf(at time.Time) string { return strconv.FormatInt(at.Unix(), 36) }

// Pruning keeps every record a retry within the window could still need,
// stamps records written before #303, and drops the rest. It is idempotent,
// so two writers that read the same labels write the same records.
func TestPruneDetachRecords(t *testing.T) {
	t.Run("sub-second boundary", pruneSubSecondBoundary)
	now := time.Unix(1_700_000_000, 0).UTC()
	const grace = backend.ClientTokenGrace
	req := strings.Repeat("ab", 16)
	longDevice := "/dev/" + strings.Repeat("x", 20) // 25 bytes: no room for a stamp
	raw := map[string]string{
		"env":                         "dev",
		labelImage:                    "ami-0123456789abcdef0",
		labelDetachPrefix + "vol-a":   req + " /dev/sdf " + stampOf(now.Add(-time.Hour)),
		labelDetachOpPrefix + "vol-a": "0000000000000001 0123456789abcdef",
		labelDetachPrefix + "vol-b":   req + " /dev/sdg " + stampOf(now.Add(-backend.ClientTokenWindow-grace-time.Second)),
		labelDetachOpPrefix + "vol-b": "0000000000000002 0123456789abcdef",
		labelDetachPrefix + "vol-c":   req + " /dev/sdh",
		labelDetachPrefix + "vol-d":   req + " /dev/sdi " + stampOf(now.Add(time.Hour)),
		labelDetachPrefix + "vol-e":   req + " /dev/sdj " + stampOf(now.Add(-backend.ClientTokenWindow-grace)),
		labelDetachOpPrefix + "vol-f": "0000000000000003 0123456789abcdef",
		labelDetachPrefix + "vol-g":   req + " " + longDevice,
		labelDetachPrefix + "vol-h":   "garbage",
		labelDetachPrefix + "vol-i":   req + " /dev/sdk notastamp!",
	}
	want := map[string]string{
		labelDetachPrefix + "vol-a":   raw[labelDetachPrefix+"vol-a"],
		labelDetachOpPrefix + "vol-a": raw[labelDetachOpPrefix+"vol-a"],
		// Written before #303: the window starts now.
		labelDetachPrefix + "vol-c": req + " /dev/sdh " + stampOf(now),
		// A stamp ahead of this clock is another replica's skew, not expiry.
		labelDetachPrefix + "vol-d": raw[labelDetachPrefix+"vol-d"],
		// Exactly the window and the grace old is still within it.
		labelDetachPrefix + "vol-e": raw[labelDetachPrefix+"vol-e"],
		// Too long to stamp: kept as it is, as before #303.
		labelDetachPrefix + "vol-g": raw[labelDetachPrefix+"vol-g"],
	}
	got := pruneDetachRecords(raw, now)
	if !maps.Equal(got, want) {
		t.Fatalf("pruned records:\n got %v\nwant %v", got, want)
	}
	again := pruneDetachRecords(got, now)
	if !maps.Equal(again, got) {
		t.Fatalf("pruning twice changed the records:\n got %v\nwant %v", again, got)
	}
	if rec, ok := detachReplayFrom(got, "vol-c"); !ok || rec.requestHex != req || rec.device != "/dev/sdh" {
		t.Fatalf("stamped record reads back as %+v %v", rec, ok)
	}
	if rec, ok := detachReplayFrom(got, "vol-g"); !ok || rec.device != longDevice {
		t.Fatalf("unstamped record reads back as %+v %v", rec, ok)
	}
}

// A detach accepted part way into a second is stamped with the next second,
// so the stamp is never earlier than the time compute starts remembering the
// request id. Pruning keeps the record until it is more than
// backend.ClientTokenWindow and backend.ClientTokenGrace past that stamp,
// which covers the compute call that follows the clock read (#316 review).
func pruneSubSecondBoundary(t *testing.T) {
	const grace = backend.ClientTokenGrace
	req := strings.Repeat("cd", 16)
	accepted := time.Unix(1_700_000_000, 999_000_000).UTC()
	stamp := time.Unix(1_700_000_001, 0).UTC()
	value := detachRecordValue(req, "/dev/sdf", accepted)
	if want := req + " /dev/sdf " + stampOf(stamp); value != want {
		t.Fatalf("record %q, want the stamp rounded up: %q", value, want)
	}
	if exact := detachRecordValue(req, "/dev/sdf", stamp); exact != value {
		t.Fatalf("a whole second is its own stamp: %q, want %q", exact, value)
	}
	raw := map[string]string{labelDetachPrefix + "vol-a": value}
	for _, tc := range []struct {
		label string
		now   time.Time
		kept  bool
	}{
		{"a second past the window from the accept time", accepted.Add(backend.ClientTokenWindow + time.Second), true},
		{"the window and the grace past the stamp", stamp.Add(backend.ClientTokenWindow + grace), true},
		{"a nanosecond later", stamp.Add(backend.ClientTokenWindow + grace + time.Nanosecond), false},
	} {
		_, kept := pruneDetachRecords(raw, tc.now)[labelDetachPrefix+"vol-a"]
		if kept != tc.kept {
			t.Errorf("%s: kept %v, want %v", tc.label, kept, tc.kept)
		}
	}
}

// capacityWorld is one running instance with a root volume and n data
// volumes, behind a compute stub that enforces the label limits.
func capacityWorld(
	t *testing.T, n int,
) (*detachWorld, computeClient, string, []resource.VolumeID, resource.InstanceID) {
	t.Helper()
	account := mustAccount(t)
	projectID := project(account)
	const instID = "i-0123456789abcdef0"
	holder := observedInstance(projectID, instID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		computev1.InstancePower_INSTANCE_POWER_RUNNING)
	holder.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, "vol-0123456789abcdef0"), DeviceName: "boot", Boot: true},
	}
	var vols []*storagev1.Volume
	var ids []resource.VolumeID
	for i := range n {
		id := fmt.Sprintf("vol-%017x", i+1)
		parsed, err := resource.Parse[resource.VolumeID](id)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, parsed)
		holder.Spec.Volumes = append(holder.Spec.Volumes, &computev1.VolumeAttachment{
			Volume: volumeName(projectID, id), DeviceName: fmt.Sprintf("/dev/sd%c", 'f'+i),
		})
		vols = append(vols, observedVolume(projectID, id, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, instID))
	}
	world := &detachWorld{
		inst: []*computev1.Instance{holder}, vol: vols[0], more: vols[1:],
		byRequest: map[string]*detachRecord{}, maxLabels: labelMax,
	}
	client := dialDetachWorld(t, world)
	inst, err := resource.Parse[resource.InstanceID](instID)
	if err != nil {
		t.Fatal(err)
	}
	return world, client, instanceName(projectID, instID), ids, inst
}

// An instance that detached more volumes than the label budget holds still
// takes 50 user tags: records past the window are pruned on every write, and
// at most backend.MaxDetachReplays remain within it.
func TestDetachRecordsLeaveRoomForFiftyTags(t *testing.T) {
	world, client, name, vols, inst := capacityWorld(t, 9)
	start := time.Unix(1_700_000_000, 0).UTC()
	var mu sync.Mutex
	now := start
	client.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	at := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = start.Add(d)
	}
	// A record from before #303 and an operation id whose record is gone.
	world.mu.Lock()
	world.inst[0].Labels[labelDetachPrefix+"vol-0aaaaaaaaaaaaaaaa"] = strings.Repeat("ab", 16) + " /dev/sdz"
	world.inst[0].Labels[labelDetachOpPrefix+"vol-0bbbbbbbbbbbbbbbb"] = "0000000000000001 0123456789abcdef"
	world.mu.Unlock()

	ctx := context.Background()
	scope := backend.Scope{Account: mustAccount(t)}
	mut := func(i int) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: fmt.Sprintf("k-cap-%d", i), Fingerprint: fmt.Sprintf("fp-cap-%d", i)}
	}
	req := func(i int) resource.DetachVolumeRequest {
		return resource.DetachVolumeRequest{VolumeID: vols[i], InstanceID: inst}
	}
	origs := map[int]resource.Accepted[resource.VolumeAttachment]{}
	// Seven client-token detaches nine hours apart: more than the budget
	// holds, but never more than four within one window.
	for i := range 7 {
		at(time.Duration(i) * 9 * time.Hour)
		acc, err := client.DetachVolume(ctx, mut(i), req(i))
		if err != nil {
			t.Fatalf("detach %d at %dh: %v", i, i*9, err)
		}
		origs[i] = acc
	}
	records := func() []string {
		var keys []string
		for key := range world.labelsOf(name) {
			if detachRecordKey(key) {
				keys = append(keys, key)
			}
		}
		return keys
	}
	// At 54h the window holds the detaches at 36h, 45h and 54h.
	for _, key := range records() {
		_, vol, _ := strings.Cut(key, "-vol-")
		vol = "vol-" + vol
		if vol != vols[4].String() && vol != vols[5].String() && vol != vols[6].String() {
			t.Errorf("record %s outlived the window", key)
		}
	}

	at(55 * time.Hour)
	tags := map[string]string{}
	for i := range resource.MaxTags {
		tags[fmt.Sprintf("k%02d", i)] = "v"
	}
	if _, err := client.CreateTags(ctx, mut(100), resource.CreateTagsRequest{
		IDs: []resource.InstanceID{inst}, Tags: tags,
	}); err != nil {
		t.Fatalf("CreateTags with %d tags: %v", len(tags), err)
	}
	// The fourth detach within the window fills the budget next to 50 tags.
	acc, err := client.DetachVolume(ctx, mut(7), req(7))
	if err != nil {
		t.Fatalf("fourth detach within the window, with 50 tags: %v", err)
	}
	origs[7] = acc
	labels := world.labelsOf(name)
	if len(labels) > labelMax {
		t.Fatalf("%d labels, compute holds %d", len(labels), labelMax)
	}
	world.mu.Lock()
	stored := proto.Clone(world.inst[0]).(*computev1.Instance)
	world.mu.Unlock()
	model, err := instanceModel(stored)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Tags) != resource.MaxTags {
		t.Fatalf("instance has %d tags, want %d", len(model.Tags), resource.MaxTags)
	}
	if got := len(records()); got != 2*backend.MaxDetachReplays {
		t.Fatalf("%d record labels, want %d", got, 2*backend.MaxDetachReplays)
	}

	if _, err := client.DetachVolume(ctx, mut(8), req(8)); resource.CodeOf(err) != resource.CodeResourceExhausted {
		t.Fatalf("fifth detach within the window: %v, want resource exhausted", err)
	}
	if vols := world.volumeNames(name); len(vols) != 2 {
		t.Fatalf("a refused detach changed the spec: %v", vols)
	}
	minted := mut(9)
	minted.MintedToken = true
	if _, err := client.DetachVolume(ctx, minted, req(8)); err != nil {
		t.Fatalf("detach with a minted token at the budget: %v", err)
	}
	if _, ok := world.labelsOf(name)[labelDetachPrefix+vols[8].String()]; ok {
		t.Fatal("a minted detach wrote a record")
	}
	for i := 4; i <= 7; i++ {
		again, err := client.DetachVolume(ctx, mut(i), resource.DetachVolumeRequest{VolumeID: vols[i]})
		if err != nil {
			t.Fatalf("retry %d within the window: %v", i, err)
		}
		if again.Operation.ID != origs[i].Operation.ID || again.Items[0].Device != origs[i].Items[0].Device {
			t.Fatalf("retry %d gave op %s %+v, want op %s %+v",
				i, again.Operation.ID, again.Items[0], origs[i].Operation.ID, origs[i].Items[0])
		}
	}
	if _, err := client.CreateTags(ctx, mut(101), resource.CreateTagsRequest{
		IDs: []resource.InstanceID{inst}, Tags: map[string]string{"one-more": "v"},
	}); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("tag %d: %v, want too many", resource.MaxTags+1, err)
	}
}

// A retry whose operation id was never saved resends the original update by
// request id. Its payload must carry the record's original stamp, not the
// retry's clock, or compute answers a fingerprint mismatch.
func TestDetachRecoveryResendsTheOriginalStamp(t *testing.T) {
	t.Run("a record that expired meanwhile", recoveryKeepsExpiredRecords)
	world, client, name, vols, inst := capacityWorld(t, 1)
	start := time.Unix(1_700_000_000, 0).UTC()
	var offset atomic.Int64
	client.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
	m := backend.Mutation{Scope: backend.Scope{Account: mustAccount(t)}, Key: "k-stamp", Fingerprint: "fp-stamp"}
	req := resource.DetachVolumeRequest{VolumeID: vols[0], InstanceID: inst}
	world.mu.Lock()
	world.failSameSpec = 1 // the write that saves the operation id fails
	world.mu.Unlock()
	if _, err := client.DetachVolume(context.Background(), m, req); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("interrupted detach: %v", err)
	}
	offset.Add(int64(time.Hour))
	again, err := client.DetachVolume(context.Background(), m, req)
	if err != nil {
		t.Fatalf("retry an hour later: %v", err)
	}
	world.mu.Lock()
	rec := world.byRequest[requestUUID(m.Key, "detach")]
	world.mu.Unlock()
	op, err := operationFrom(rec.op, resource.ServiceCompute)
	if err != nil {
		t.Fatal(err)
	}
	if again.Operation.ID != op.ID {
		t.Fatalf("retry gave op %s, want %s", again.Operation.ID, op.ID)
	}
	if got := world.labelsOf(name)[labelDetachPrefix+vols[0].String()]; !strings.HasSuffix(got, " "+stampOf(start)) {
		t.Fatalf("record %q lost its original stamp %s", got, stampOf(start))
	}
}

// A recovery resend carries every detach record exactly as the interrupted
// write stored it. Record A expires between B's write and B's recovery; had
// the resend pruned it, the payload would differ from B's original and
// compute would answer a fingerprint mismatch (#316 review).
func recoveryKeepsExpiredRecords(t *testing.T) {
	const grace = backend.ClientTokenGrace
	world, client, name, vols, inst := capacityWorld(t, 2)
	start := time.Unix(1_700_000_000, 0).UTC()
	var offset atomic.Int64
	client.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
	scope := backend.Scope{Account: mustAccount(t)}
	ctx := context.Background()
	mA := backend.Mutation{Scope: scope, Key: "k-expire-a", Fingerprint: "fp-expire-a"}
	reqA := resource.DetachVolumeRequest{VolumeID: vols[0], InstanceID: inst}
	if _, err := client.DetachVolume(ctx, mA, reqA); err != nil {
		t.Fatalf("detach A: %v", err)
	}
	recordA := labelDetachPrefix + vols[0].String()
	offset.Store(int64(backend.ClientTokenWindow - time.Minute))
	mB := backend.Mutation{Scope: scope, Key: "k-expire-b", Fingerprint: "fp-expire-b"}
	reqB := resource.DetachVolumeRequest{VolumeID: vols[1], InstanceID: inst}
	world.mu.Lock()
	world.failSameSpec = 1 // the write that saves B's operation id fails
	world.mu.Unlock()
	if _, err := client.DetachVolume(ctx, mB, reqB); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("interrupted detach B: %v", err)
	}
	if _, ok := world.labelsOf(name)[recordA]; !ok {
		t.Fatal("B's write dropped A's record while A was within the window")
	}
	// A is now past the window and the grace; B is a few minutes old.
	offset.Store(int64(backend.ClientTokenWindow + grace + 2*time.Minute))
	again, err := client.DetachVolume(ctx, mB, reqB)
	if err != nil {
		t.Fatalf("B's recovery after A expired: %v", err)
	}
	world.mu.Lock()
	rec := world.byRequest[requestUUID(mB.Key, "detach")]
	world.mu.Unlock()
	op, err := operationFrom(rec.op, resource.ServiceCompute)
	if err != nil {
		t.Fatal(err)
	}
	if again.Operation.ID != op.ID {
		t.Fatalf("recovery gave op %s, want B's %s", again.Operation.ID, op.ID)
	}
}
