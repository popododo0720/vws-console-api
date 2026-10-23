package grpcclient

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

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
	t.Run("held while a recovery is pending", pruneHeldForRecovery)
	t.Run("a record written before #303 during a hold", pruneUnstampedDuringHold)
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
		labelDetachOpPrefix + "vol-c": "0000000000000004 0123456789abcdef",
		labelDetachPrefix + "vol-d":   req + " /dev/sdi " + stampOf(now.Add(time.Hour)),
		labelDetachOpPrefix + "vol-d": "0000000000000005 0123456789abcdef",
		labelDetachPrefix + "vol-e":   req + " /dev/sdj " + stampOf(now.Add(-backend.ClientTokenWindow-grace)),
		labelDetachOpPrefix + "vol-e": "0000000000000006 0123456789abcdef",
		labelDetachOpPrefix + "vol-f": "0000000000000003 0123456789abcdef",
		labelDetachPrefix + "vol-g":   req + " " + longDevice,
		labelDetachOpPrefix + "vol-g": "0000000000000007 0123456789abcdef",
		labelDetachPrefix + "vol-h":   "garbage",
		labelDetachPrefix + "vol-i":   req + " /dev/sdk notastamp!",
	}
	want := map[string]string{
		labelDetachPrefix + "vol-a":   raw[labelDetachPrefix+"vol-a"],
		labelDetachOpPrefix + "vol-a": raw[labelDetachOpPrefix+"vol-a"],
		// Written before #303: the window starts now.
		labelDetachPrefix + "vol-c":   req + " /dev/sdh " + stampOf(now),
		labelDetachOpPrefix + "vol-c": raw[labelDetachOpPrefix+"vol-c"],
		// A stamp ahead of this clock is another replica's skew, not expiry.
		labelDetachPrefix + "vol-d":   raw[labelDetachPrefix+"vol-d"],
		labelDetachOpPrefix + "vol-d": raw[labelDetachOpPrefix+"vol-d"],
		// Exactly the window and the grace old is still within it.
		labelDetachPrefix + "vol-e":   raw[labelDetachPrefix+"vol-e"],
		labelDetachOpPrefix + "vol-e": raw[labelDetachOpPrefix+"vol-e"],
		// Too long to stamp: kept as it is, as before #303.
		labelDetachPrefix + "vol-g":   raw[labelDetachPrefix+"vol-g"],
		labelDetachOpPrefix + "vol-g": raw[labelDetachOpPrefix+"vol-g"],
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

// A record within the window with no saved operation id is a detach whose
// operation id write failed; its retry resends the original update by
// request id, and that update carried every record then stored. While such
// a record is within the window, pruning keeps the expired records too, so
// the resend still matches. A held record is not within the window, so it
// does not count toward backend.MaxDetachReplays. Once the operation id is
// saved, or the pending record expires, the expired records go (#319 review).
func pruneHeldForRecovery(t *testing.T) {
	const grace = backend.ClientTokenGrace
	now := time.Unix(1_700_000_000, 0).UTC()
	req := strings.Repeat("ef", 16)
	expired := stampOf(now.Add(-backend.ClientTokenWindow - grace - time.Second))
	pending := map[string]string{
		labelDetachPrefix + "vol-a":   req + " /dev/sdf " + expired,
		labelDetachOpPrefix + "vol-a": "0000000000000001 0123456789abcdef",
		labelDetachPrefix + "vol-b":   req + " /dev/sdg " + stampOf(now.Add(-time.Hour)),
	}
	got := pruneDetachRecords(pending, now)
	if !maps.Equal(got, pending) {
		t.Fatalf("records with a recovery pending:\n got %v\nwant %v", got, pending)
	}
	if n := detachRecordsInWindow(pending, now, ""); n != 1 {
		t.Fatalf("%d records within the window, want 1: a held record is not counted", n)
	}
	saved := maps.Clone(pending)
	saved[labelDetachOpPrefix+"vol-b"] = "0000000000000002 0123456789abcdef"
	want := map[string]string{
		labelDetachPrefix + "vol-b":   saved[labelDetachPrefix+"vol-b"],
		labelDetachOpPrefix + "vol-b": saved[labelDetachOpPrefix+"vol-b"],
	}
	if got := pruneDetachRecords(saved, now); !maps.Equal(got, want) {
		t.Fatalf("records once the operation id is saved:\n got %v\nwant %v", got, want)
	}
	later := now.Add(backend.ClientTokenWindow + grace)
	if got := pruneDetachRecords(pending, later); len(got) != 0 {
		t.Fatalf("records once the pending record expired: %v, want none", got)
	}
}

// Kept expired records still count toward compute's 64 labels: a write they
// would push past it is the tag capacity error, not a truncated label map.
func TestHeldDetachRecordsKeepTheLabelGuard(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	req := strings.Repeat("ef", 16)
	expired := stampOf(now.Add(-backend.ClientTokenWindow - backend.ClientTokenGrace - time.Second))
	raw := map[string]string{
		labelDetachPrefix + "vol-pending": req + " /dev/sdz " + stampOf(now.Add(-time.Hour)),
	}
	for i := range 2 * backend.MaxDetachReplays {
		vol := fmt.Sprintf("vol-held-%d", i)
		raw[labelDetachPrefix+vol] = req + " /dev/sdf " + expired
		raw[labelDetachOpPrefix+vol] = "0000000000000001 0123456789abcdef"
	}
	inst := resource.Instance{Tags: map[string]string{}}
	for i := range resource.MaxTags {
		inst.Tags[fmt.Sprintf("k%02d", i)] = "v"
	}
	_, err := instanceUpdateLabels(inst, raw, resource.ActionCreateTags, "fp", nil, now)
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("50 tags next to %d held records: %v, want the tag capacity error", 2*backend.MaxDetachReplays, err)
	}
	inst.Tags = map[string]string{"env": "prod"}
	labels, err := instanceUpdateLabels(inst, raw, resource.ActionCreateTags, "fp", nil, now)
	if err != nil {
		t.Fatalf("one tag next to the held records: %v", err)
	}
	if _, ok := labels[labelDetachPrefix+"vol-held-0"]; !ok {
		t.Fatal("a held record was dropped while the recovery is pending")
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
	t.Run("an intervening tag write", func(t *testing.T) { recoveryAfterInterveningWrite(t, interveningTags) })
	t.Run("an intervening stop", func(t *testing.T) { recoveryAfterInterveningWrite(t, interveningStop) })
	t.Run("a record written before #303, an intervening tag write", func(t *testing.T) {
		recoveryOfARecordWrittenBefore303(t, interveningTags)
	})
	t.Run("a record written before #303, an intervening stop", func(t *testing.T) {
		recoveryOfARecordWrittenBefore303(t, interveningStop)
	})
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

func interveningTags(ctx context.Context, client computeClient, scope backend.Scope, inst resource.InstanceID) error {
	return tagEnvProd(ctx, client, scope, inst, "k-tag-2")
}

// tagEnvProd writes the same tag value under a new client token each time.
func tagEnvProd(
	ctx context.Context, client computeClient, scope backend.Scope, inst resource.InstanceID, key string,
) error {
	_, err := client.CreateTags(ctx, backend.Mutation{Scope: scope, Key: key, Fingerprint: "fp-" + key},
		resource.CreateTagsRequest{IDs: []resource.InstanceID{inst}, Tags: map[string]string{"env": "prod"}})
	return err
}

func interveningStop(ctx context.Context, client computeClient, scope backend.Scope, inst resource.InstanceID) error {
	_, err := client.StopInstances(ctx, backend.Mutation{Scope: scope, Key: "k-stop", Fingerprint: "fp-stop"},
		resource.StopInstancesRequest{IDs: []resource.InstanceID{inst}})
	return err
}

// B's record is written but its operation id is not. A expires, and another
// label write on the instance (the same tag value again, or a stop) runs
// before B's retry. That write must not prune A while B's recovery is
// pending, or B's resend differs from B's original update and compute
// answers a fingerprint mismatch. Once B's operation id is saved, the next
// write prunes A (#319 review).
func recoveryAfterInterveningWrite(
	t *testing.T, write func(context.Context, computeClient, backend.Scope, resource.InstanceID) error,
) {
	const grace = backend.ClientTokenGrace
	world, client, name, vols, inst := capacityWorld(t, 2)
	start := time.Unix(1_700_000_000, 0).UTC()
	var offset atomic.Int64
	client.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
	scope := backend.Scope{Account: mustAccount(t)}
	ctx := context.Background()
	if err := tagEnvProd(ctx, client, scope, inst, "k-tag-1"); err != nil {
		t.Fatalf("first tag write: %v", err)
	}
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
	offset.Store(int64(backend.ClientTokenWindow + grace + 2*time.Minute))
	if err := write(ctx, client, scope, inst); err != nil {
		t.Fatalf("intervening write: %v", err)
	}
	if _, ok := world.labelsOf(name)[recordA]; !ok {
		t.Error("the intervening write pruned A while B's recovery was pending")
	}
	again, err := client.DetachVolume(ctx, mB, reqB)
	if err != nil {
		t.Fatalf("B's recovery after the intervening write: %v", err)
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
	if _, ok := world.labelsOf(name)[labelDetachOpPrefix+vols[1].String()]; !ok {
		t.Fatal("B's recovery did not save its operation id")
	}
	if err := tagEnvProd(ctx, client, scope, inst, "k-tag-3"); err != nil {
		t.Fatalf("tag write after B's recovery: %v", err)
	}
	if _, ok := world.labelsOf(name)[recordA]; ok {
		t.Fatal("A was kept after B's operation id was saved")
	}
}

// A detach saves its operation id in a second label write. Held expired
// records take labels without counting toward backend.MaxDetachReplays, so
// a detach can fit compute's 64 labels on its first write and have no room
// for its vws-dop- label. That detach is the tag capacity error before
// compute is called, and changes nothing; a same-token retry is refused the
// same way, never answered for a detach that happened (#319 review, #322).
// The pending detach next to it has no operation id yet either, and its
// label is reserved too (#327 review): 49 tags leave no room for both.
func TestDetachLeavesRoomForItsOperationID(t *testing.T) {
	t.Run("the operation id would be label 65", func(t *testing.T) { detachOpIDBoundary(t, resource.MaxTags, false) })
	t.Run("the pending detach's reserved label would be 65", func(t *testing.T) {
		detachOpIDBoundary(t, resource.MaxTags-1, false)
	})
	t.Run("the operation id is label 63, next to the reserved label 64", func(t *testing.T) {
		detachOpIDBoundary(t, resource.MaxTags-2, true)
	})
}

// heldRecordsNextToTags holds three expired records next to a pending one
// (its operation id write failed) and a normal one, then adds tagCount tags
// of one label each: 13+tagCount labels, one of them reserved for the
// pending detach's operation id.
func heldRecordsNextToTags(t *testing.T, tagCount int) (
	*detachWorld, computeClient, string, []resource.VolumeID, resource.InstanceID, backend.Scope,
) {
	t.Helper()
	world, client, name, vols, inst := capacityWorld(t, 6)
	start := time.Unix(1_700_000_000, 0).UTC()
	var offset atomic.Int64
	client.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
	scope := backend.Scope{Account: mustAccount(t)}
	ctx := context.Background()
	for i := range 3 {
		m := backend.Mutation{Scope: scope, Key: fmt.Sprintf("k-old-%d", i), Fingerprint: fmt.Sprintf("fp-old-%d", i)}
		req := resource.DetachVolumeRequest{VolumeID: vols[i], InstanceID: inst}
		if _, err := client.DetachVolume(ctx, m, req); err != nil {
			t.Fatalf("detach %d: %v", i, err)
		}
	}
	offset.Store(int64(backend.ClientTokenWindow - time.Minute))
	world.mu.Lock()
	world.failSameSpec = 1 // the pending detach's operation id write fails
	world.mu.Unlock()
	mP := backend.Mutation{Scope: scope, Key: "k-pending", Fingerprint: "fp-pending"}
	reqP := resource.DetachVolumeRequest{VolumeID: vols[3], InstanceID: inst}
	if _, err := client.DetachVolume(ctx, mP, reqP); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("interrupted pending detach: %v", err)
	}
	offset.Store(int64(backend.ClientTokenWindow + backend.ClientTokenGrace + 2*time.Minute))
	mX := backend.Mutation{Scope: scope, Key: "k-extra", Fingerprint: "fp-extra"}
	reqX := resource.DetachVolumeRequest{VolumeID: vols[4], InstanceID: inst}
	if _, err := client.DetachVolume(ctx, mX, reqX); err != nil {
		t.Fatalf("extra detach: %v", err)
	}
	tags := map[string]string{}
	for i := range tagCount {
		tags[fmt.Sprintf("k%02d", i)] = "v"
	}
	if _, err := client.CreateTags(ctx, backend.Mutation{Scope: scope, Key: "k-tags", Fingerprint: "fp-tags"},
		resource.CreateTagsRequest{IDs: []resource.InstanceID{inst}, Tags: tags}); err != nil {
		t.Fatalf("%d tags next to the held records: %v", tagCount, err)
	}
	if n := len(world.labelsOf(name)); n != 13+tagCount {
		t.Fatalf("%d labels after %d tags, want %d", n, tagCount, 13+tagCount)
	}
	return world, client, name, vols, inst, scope
}

// detachOpIDBoundary detaches one more volume next to heldRecordsNextToTags.
func detachOpIDBoundary(t *testing.T, tagCount int, fits bool) {
	world, client, name, vols, inst, scope := heldRecordsNextToTags(t, tagCount)
	ctx := context.Background()
	spec := world.volumeNames(name)
	mN := backend.Mutation{Scope: scope, Key: "k-new", Fingerprint: "fp-new"}
	reqN := resource.DetachVolumeRequest{VolumeID: vols[5], InstanceID: inst}
	first, err := client.DetachVolume(ctx, mN, reqN)
	if !fits {
		for attempt := range 2 {
			if resource.CodeOf(err) != resource.CodeInvalidArgument {
				t.Fatalf("attempt %d: %v, want the tag capacity error", attempt, err)
			}
			assertDetachRoomError(t, err)
			world.mu.Lock()
			_, sent := world.byRequest[requestUUID(mN.Key, "detach")]
			world.mu.Unlock()
			if sent {
				t.Fatalf("attempt %d: the refused detach reached compute", attempt)
			}
			if got := world.volumeNames(name); !slices.Equal(got, spec) {
				t.Fatalf("attempt %d: the refused detach changed the spec: %v, want %v", attempt, got, spec)
			}
			if _, ok := world.labelsOf(name)[labelDetachPrefix+vols[5].String()]; ok {
				t.Fatalf("attempt %d: the refused detach wrote a record", attempt)
			}
			_, err = client.DetachVolume(ctx, mN, reqN)
		}
		return
	}
	if err != nil {
		t.Fatalf("detach with room for its operation id: %v", err)
	}
	labels := world.labelsOf(name)
	if want := 13 + tagCount + 2; len(labels) != want {
		t.Fatalf("%d labels, want %d", len(labels), want)
	}
	if _, ok := labels[labelDetachOpPrefix+vols[5].String()]; !ok {
		t.Fatal("the operation id was not saved")
	}
	again, err := client.DetachVolume(ctx, mN, reqN)
	if err != nil || again.Operation.ID != first.Operation.ID {
		t.Fatalf("same-token retry: op %s, %v; want op %s", again.Operation.ID, err, first.Operation.ID)
	}
}

// A detach's operation id label is reserved from its first write until the
// id is saved: a label write in between that would take it is the tag
// capacity error and writes nothing, and the detach completes with its id
// saved (#327 review). With 49 tags there is no room for the detach next
// to the pending one's reserved label, so it is refused before compute is
// called and no write can race it.
func TestATagWriteCannotTakeAPendingOperationIDsRoom(t *testing.T) {
	t.Run("49 tags: the detach is refused before a tag write can race it", func(t *testing.T) {
		tagWriteDuringOpIDSave(t, resource.MaxTags-1, false)
	})
	t.Run("48 tags: the tag write is refused and the detach saves its id", func(t *testing.T) {
		tagWriteDuringOpIDSave(t, resource.MaxTags-2, true)
	})
}

// tagWriteDuringOpIDSave sends CreateTags with one more tag between a
// detach's first write and the write that saves its operation id.
func tagWriteDuringOpIDSave(t *testing.T, tagCount int, fits bool) {
	world, client, name, vols, inst, scope := heldRecordsNextToTags(t, tagCount)
	ctx := context.Background()
	mN := backend.Mutation{Scope: scope, Key: "k-new", Fingerprint: "fp-new"}
	reqN := resource.DetachVolumeRequest{VolumeID: vols[5], InstanceID: inst}
	extra := fmt.Sprintf("k%02d", tagCount)
	var once sync.Once
	var raced bool
	var tagErr error
	world.mu.Lock()
	world.afterUpdate = func(req *computev1.UpdateInstanceRequest, err error) {
		if err != nil || req.GetRequestId() != requestUUID(mN.Key, "detach") {
			return
		}
		once.Do(func() {
			raced = true
			_, tagErr = client.CreateTags(ctx,
				backend.Mutation{Scope: scope, Key: "k-tag-race", Fingerprint: "fp-tag-race"},
				resource.CreateTagsRequest{IDs: []resource.InstanceID{inst}, Tags: map[string]string{extra: "v"}})
		})
	}
	world.mu.Unlock()
	first, err := client.DetachVolume(ctx, mN, reqN)
	if !fits {
		if resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Fatalf("detach with %d tags: %v, want the capacity error before compute", tagCount, err)
		}
		if raced {
			t.Fatalf("the refused detach reached compute (%v)", err)
		}
		assertDetachRoomError(t, err)
		return
	}
	if !raced {
		t.Fatal("the tag write did not run between the detach's writes")
	}
	if resource.CodeOf(tagErr) != resource.CodeInvalidArgument {
		t.Fatalf("tag write into the reserved label: %v, want the tag capacity error", tagErr)
	}
	if err != nil {
		t.Fatalf("detach whose label was reserved: %v", err)
	}
	labels := world.labelsOf(name)
	if _, ok := labels[labelDetachOpPrefix+vols[5].String()]; !ok {
		t.Fatal("the operation id was not saved")
	}
	if _, ok := labels[extra]; ok {
		t.Fatal("the refused tag write was stored")
	}
	if want := 13 + tagCount + 2; len(labels) != want {
		t.Fatalf("%d labels, want %d", len(labels), want)
	}
	again, err := client.DetachVolume(ctx, mN, reqN)
	if err != nil || again.Operation.ID != first.Operation.ID {
		t.Fatalf("same-token retry: op %s, %v; want op %s", again.Operation.ID, err, first.Operation.ID)
	}
}

// assertDetachRoomError checks that a DetachVolume refused for label room
// names the volume and the detach record, not tags (#327 review).
func assertDetachRoomError(t *testing.T, err error) {
	t.Helper()
	e := resource.AsError(err)
	if e.Field != "VolumeId" || !strings.Contains(e.Message, "detach") || strings.Contains(e.Message, "tags") {
		t.Fatalf("refused detach: field %q, message %q; want VolumeId and a message about the detach record",
			e.Field, e.Message)
	}
}

// A record written before #303 has no stamp. If its operation id write
// failed, its retry resends that write by request id, unstamped. Another
// label write before the retry must leave the record exactly as stored, or
// the resend carries a stamp the original did not and compute answers a
// fingerprint mismatch. Once the operation id is saved, the next write
// stamps it (#319 review, #322).
func recoveryOfARecordWrittenBefore303(
	t *testing.T, write func(context.Context, computeClient, backend.Scope, resource.InstanceID) error,
) {
	world, client, name, vols, inst := capacityWorld(t, 1)
	start := time.Unix(1_700_000_000, 0).UTC()
	var offset atomic.Int64
	client.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
	scope := backend.Scope{Account: mustAccount(t)}
	ctx := context.Background()
	if err := tagEnvProd(ctx, client, scope, inst, "k-tag-1"); err != nil {
		t.Fatalf("first tag write: %v", err)
	}
	m := backend.Mutation{Scope: scope, Key: "k-legacy", Fingerprint: "fp-legacy"}
	req := resource.DetachVolumeRequest{VolumeID: vols[0], InstanceID: inst}
	world.mu.Lock()
	world.failSameSpec = 1 // the write that saves the operation id fails
	world.mu.Unlock()
	if _, err := client.DetachVolume(ctx, m, req); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("interrupted detach: %v", err)
	}
	// Make that detach the one code before #303 sent: the same update with
	// an unstamped record, as compute stored it under its request id.
	recordKey := labelDetachPrefix + vols[0].String()
	requestID := requestUUID(m.Key, "detach")
	world.mu.Lock()
	stored := world.inst[0]
	labels := maps.Clone(stored.GetLabels())
	requestHex, device, _, stamped, ok := parseDetachRecord(labels[recordKey])
	if !ok || !stamped {
		world.mu.Unlock()
		t.Fatalf("record %q, want a stamped record to rewrite", labels[recordKey])
	}
	legacy := requestHex + " " + device
	labels[recordKey] = legacy
	fp, err := detachReqFingerprint(&computev1.UpdateInstanceRequest{
		RequestId:  requestID,
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.volumes", "labels"}},
		Instance: &computev1.Instance{
			Name: stored.GetName(), Labels: labels,
			Spec: &computev1.InstanceSpec{Volumes: stored.GetSpec().GetVolumes()},
		},
	})
	if err != nil {
		world.mu.Unlock()
		t.Fatal(err)
	}
	stored.Labels = labels
	world.byRequest[requestID].fp = fp
	op, err := operationFrom(world.byRequest[requestID].op, resource.ServiceCompute)
	world.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	offset.Store(int64(time.Hour))
	if err := write(ctx, client, scope, inst); err != nil {
		t.Fatalf("intervening write: %v", err)
	}
	if got := world.labelsOf(name)[recordKey]; got != legacy {
		t.Errorf("the intervening write changed the pending record: %q, want %q as stored", got, legacy)
	}
	again, err := client.DetachVolume(ctx, m, req)
	if err != nil {
		t.Fatalf("recovery after the intervening write: %v", err)
	}
	if again.Operation.ID != op.ID {
		t.Fatalf("recovery gave op %s, want %s", again.Operation.ID, op.ID)
	}
	if _, ok := world.labelsOf(name)[labelDetachOpPrefix+vols[0].String()]; !ok {
		t.Fatal("the recovery did not save its operation id")
	}
	if err := tagEnvProd(ctx, client, scope, inst, "k-tag-3"); err != nil {
		t.Fatalf("tag write after the recovery: %v", err)
	}
	if got, want := world.labelsOf(name)[recordKey], legacy+" "+stampOf(start.Add(time.Hour)); got != want {
		t.Fatalf("record after the recovery: %q, want it stamped by the next write: %q", got, want)
	}
}

// During a hold a record written before #303 is left exactly as stored, and
// it does not count toward backend.MaxDetachReplays: if its retry never
// comes, other detaches still get stamped records. A record without a stamp
// was written before every stamped record, so once a stamped record has
// expired so has it: the hold it caused ends, and it is stamped like any
// record written before #303 (#322).
func pruneUnstampedDuringHold(t *testing.T) {
	const grace = backend.ClientTokenGrace
	now := time.Unix(1_700_000_000, 0).UTC()
	req := strings.Repeat("ab", 16)
	held := map[string]string{
		labelDetachPrefix + "vol-legacy": req + " /dev/sdf",
		labelDetachPrefix + "vol-a":      req + " /dev/sdg " + stampOf(now.Add(-time.Hour)),
		labelDetachOpPrefix + "vol-a":    "0000000000000001 0123456789abcdef",
	}
	if got := pruneDetachRecords(held, now); !maps.Equal(got, held) {
		t.Fatalf("records during the hold:\n got %v\nwant %v", got, held)
	}
	if n := detachRecordsInWindow(held, now, ""); n != 1 {
		t.Fatalf("%d records within the window, want 1: an unstamped record is not counted during a hold", n)
	}
	expired := maps.Clone(held)
	past := now.Add(-backend.ClientTokenWindow - grace - time.Second)
	expired[labelDetachPrefix+"vol-a"] = req + " /dev/sdg " + stampOf(past)
	want := map[string]string{labelDetachPrefix + "vol-legacy": req + " /dev/sdf " + stampOf(now)}
	if got := pruneDetachRecords(expired, now); !maps.Equal(got, want) {
		t.Fatalf("records once a stamped record expired:\n got %v\nwant %v", got, want)
	}
}
