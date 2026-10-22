package backendtest

import (
	"context"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// ClockHarness builds a fresh backend set whose clock advance moves forward.
// The backend and anything that stamps records for it share that clock.
type ClockHarness func() (set backend.Set, advance func(time.Duration))

// DetachWindow is the DetachVolume record window table (#303). A detach
// that carries a client token is remembered for backend.ClientTokenWindow,
// and its retry within the window returns that detach whatever was written
// to the instance since. An instance remembers at most
// backend.MaxDetachReplays such detaches within the window; one more is
// CodeResourceExhausted and changes nothing. A detach whose token the
// service minted can never be retried, so it is neither remembered nor
// limited.
func DetachWindow(t *testing.T, newSet ClockHarness) {
	t.Helper()
	ctx := context.Background()
	account, err := resource.Parse[resource.AccountID]("456789012345")
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account}
	mut := func(key string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: "dw-" + key, Fingerprint: "fp-dw-" + key}
	}
	minted := func(key string) backend.Mutation {
		m := mut(key)
		m.MintedToken = true
		return m
	}
	type world struct {
		set     backend.Set
		advance func(time.Duration)
		first   resource.InstanceID
	}
	open := func(t *testing.T) world {
		t.Helper()
		set, advance := newSet()
		first, _ := detachInstances(ctx, t, set, scope, mut)
		return world{set: set, advance: advance, first: first}
	}
	newVol := func(t *testing.T, w world, key string) resource.VolumeID {
		t.Helper()
		vol, err := w.set.Compute.CreateVolume(ctx, mut(key), resource.CreateVolumeRequest{
			SizeGiB: 8, Zone: resource.ZoneName,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.set.Compute.GetOperation(ctx, scope, vol.Operation.ID); err != nil {
			t.Fatal(err)
		}
		return vol.Items[0].ID
	}
	attach := func(t *testing.T, w world, key string, vol resource.VolumeID, device string) {
		t.Helper()
		acc, err := w.set.Compute.AttachVolume(ctx, mut(key), resource.AttachVolumeRequest{
			VolumeID: vol, InstanceID: w.first, Device: device,
		})
		if err != nil {
			t.Fatalf("attach %s: %v", vol, err)
		}
		if _, err := w.set.Compute.GetOperation(ctx, scope, acc.Operation.ID); err != nil {
			t.Fatal(err)
		}
	}
	detach := func(
		t *testing.T, w world, m backend.Mutation, req resource.DetachVolumeRequest,
	) resource.Accepted[resource.VolumeAttachment] {
		t.Helper()
		acc, err := w.set.Compute.DetachVolume(ctx, m, req)
		if err != nil || len(acc.Items) != 1 {
			t.Fatalf("detach %s (%s): %v %+v", req.VolumeID, m.Key, err, acc)
		}
		if _, err := w.set.Compute.GetOperation(ctx, scope, acc.Operation.ID); err != nil {
			t.Fatal(err)
		}
		return acc
	}
	replays := func(
		t *testing.T, w world, what string, m backend.Mutation, req resource.DetachVolumeRequest,
		orig resource.Accepted[resource.VolumeAttachment],
	) {
		t.Helper()
		again, err := w.set.Compute.DetachVolume(ctx, m, req)
		if err != nil {
			t.Fatalf("%s: retry %s: %v", what, m.Key, err)
		}
		got, want := again.Items[0], orig.Items[0]
		if again.Operation.ID != orig.Operation.ID || got.InstanceID != want.InstanceID || got.Device != want.Device {
			t.Fatalf("%s: retry %s gave op %s %+v, want op %s %+v",
				what, m.Key, again.Operation.ID, got, orig.Operation.ID, want)
		}
	}
	volumeState := func(t *testing.T, w world, vol resource.VolumeID) resource.Volume {
		t.Helper()
		page, err := w.set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{
			IDs: []resource.VolumeID{vol}, Page: resource.PageRequest{Size: 50},
		})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("describe %s: %v %+v", vol, err, page.Items)
		}
		return page.Items[0]
	}
	tag := func(t *testing.T, w world, key string) {
		t.Helper()
		if _, err := w.set.Compute.CreateTags(ctx, mut(key), resource.CreateTagsRequest{
			IDs: []resource.InstanceID{w.first}, Tags: map[string]string{"pass": key},
		}); err != nil {
			t.Fatalf("CreateTags %s: %v", key, err)
		}
	}

	t.Run("a retry late in the window still replays", func(t *testing.T) {
		w := open(t)
		vol := newVol(t, w, "vol-late")
		attach(t, w, "att-late", vol, "/dev/sdf")
		m := mut("det-late")
		req := resource.DetachVolumeRequest{VolumeID: vol, InstanceID: w.first}
		orig := detach(t, w, m, req)
		w.advance(backend.ClientTokenWindow - time.Minute)
		// The instance is written again, which is when records are pruned.
		tag(t, w, "late")
		replays(t, w, "a minute before the window ends", m, req, orig)
	})

	t.Run("a retry past the window never detaches again", func(t *testing.T) {
		w := open(t)
		vol := newVol(t, w, "vol-past")
		attach(t, w, "att-past", vol, "/dev/sdf")
		m := mut("det-past")
		req := resource.DetachVolumeRequest{VolumeID: vol, InstanceID: w.first}
		orig := detach(t, w, m, req)
		w.advance(backend.ClientTokenWindow + time.Minute)
		tag(t, w, "past")
		// Past the window the token may be forgotten (#305 pins the answer).
		// Either way nothing is detached again and no other detach is returned.
		again, err := w.set.Compute.DetachVolume(ctx, m, req)
		switch {
		case err == nil:
			if again.Operation.ID != orig.Operation.ID {
				t.Fatalf("retry past the window gave op %s, want %s or a conflict", again.Operation.ID, orig.Operation.ID)
			}
		case resource.CodeOf(err) != resource.CodeConflict:
			t.Fatalf("retry past the window: %v, want the original detach or a conflict", err)
		}
		if got := volumeState(t, w, vol); got.State != resource.VolumeAvailable || !got.InstanceID.IsZero() {
			t.Fatalf("volume after the retry: %+v", got)
		}
	})

	t.Run("the record budget", func(t *testing.T) {
		w := open(t)
		devices := []string{"/dev/sdf", "/dev/sdg", "/dev/sdh", "/dev/sdi", "/dev/sdj", "/dev/sdk"}
		vols := make([]resource.VolumeID, len(devices))
		for i, device := range devices {
			vols[i] = newVol(t, w, "vol-budget-"+device[len(device)-1:])
			attach(t, w, "att-budget-"+device[len(device)-1:], vols[i], device)
		}
		muts := make([]backend.Mutation, backend.MaxDetachReplays)
		reqs := make([]resource.DetachVolumeRequest, backend.MaxDetachReplays)
		origs := make([]resource.Accepted[resource.VolumeAttachment], backend.MaxDetachReplays)
		for i := range backend.MaxDetachReplays {
			muts[i] = mut("det-budget-" + devices[i][len(devices[i])-1:])
			reqs[i] = resource.DetachVolumeRequest{VolumeID: vols[i], InstanceID: w.first}
			origs[i] = detach(t, w, muts[i], reqs[i])
			w.advance(time.Minute)
		}
		over := mut("det-budget-over")
		overReq := resource.DetachVolumeRequest{VolumeID: vols[backend.MaxDetachReplays], InstanceID: w.first}
		if _, err := w.set.Compute.DetachVolume(ctx, over, overReq); resource.CodeOf(err) != resource.CodeResourceExhausted {
			t.Fatalf("detach %d with a client token: %v, want resource exhausted", backend.MaxDetachReplays+1, err)
		}
		if got := volumeState(t, w, overReq.VolumeID); got.State != resource.VolumeInUse || got.InstanceID != w.first {
			t.Fatalf("a refused detach changed the volume: %+v", got)
		}
		for i := range backend.MaxDetachReplays {
			replays(t, w, "within the budget", muts[i], reqs[i], origs[i])
		}
		// A minted token cannot be retried, so it costs no record.
		detach(t, w, minted("det-budget-minted"), overReq)
		w.advance(backend.ClientTokenWindow)
		last := mut("det-budget-last")
		lastReq := resource.DetachVolumeRequest{VolumeID: vols[len(vols)-1], InstanceID: w.first}
		lastAcc := detach(t, w, last, lastReq)
		replays(t, w, "after older records expired", last, lastReq, lastAcc)
	})
}
