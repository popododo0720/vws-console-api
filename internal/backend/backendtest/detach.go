package backendtest

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// DetachReplay is the DetachVolume client-token table (#213). A retry with
// the token and parameters of a detach that was accepted returns that
// detach, with no further action, whatever happened to the instance or the
// volume since: a tag, a stop and start, a move to another instance, or a
// reattach. The same token with other parameters is a mismatch.
//
// Each backend set gets its own account, so it may share a world with Run.
func DetachReplay(t *testing.T, newSet Harness) {
	t.Helper()
	ctx := context.Background()
	set := newSet()
	account, err := resource.Parse[resource.AccountID]("345678901234")
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account}
	mut := func(key string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: "dr-" + key, Fingerprint: "fp-dr-" + key}
	}
	first, second := detachInstances(ctx, t, set, scope, mut)
	newVol := func(t *testing.T, key string) resource.VolumeID {
		t.Helper()
		vol, err := set.Compute.CreateVolume(ctx, mut(key), resource.CreateVolumeRequest{
			SizeGiB: 8, Zone: resource.ZoneName, Type: resource.VolumeGP2,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := set.Compute.GetOperation(ctx, scope, vol.Operation.ID); err != nil {
			t.Fatal(err)
		}
		return vol.Items[0].ID
	}
	attach := func(t *testing.T, key string, vol resource.VolumeID, inst resource.InstanceID, device string) {
		t.Helper()
		if _, err := set.Compute.AttachVolume(ctx, mut(key), resource.AttachVolumeRequest{
			VolumeID: vol, InstanceID: inst, Device: device,
		}); err != nil {
			t.Fatalf("attach %s to %s: %v", vol, inst, err)
		}
	}
	detach := func(
		t *testing.T, m backend.Mutation, req resource.DetachVolumeRequest,
	) resource.Accepted[resource.VolumeAttachment] {
		t.Helper()
		acc, err := set.Compute.DetachVolume(ctx, m, req)
		if err != nil || len(acc.Items) != 1 {
			t.Fatalf("detach %s (%s): %v %+v", req.VolumeID, m.Key, err, acc)
		}
		return acc
	}
	// replays checks that a retry returns the original detach.
	replays := func(
		t *testing.T, what string, m backend.Mutation, req resource.DetachVolumeRequest,
		orig resource.Accepted[resource.VolumeAttachment],
	) {
		t.Helper()
		again, err := set.Compute.DetachVolume(ctx, m, req)
		if err != nil {
			t.Fatalf("%s: retry %s: %v", what, m.Key, err)
		}
		got, want := again.Items[0], orig.Items[0]
		if again.Operation.ID != orig.Operation.ID || got.InstanceID != want.InstanceID ||
			got.Device != want.Device || got.Status != resource.AttachmentDetaching {
			t.Fatalf("%s: retry %s gave op %s %+v, want op %s %+v",
				what, m.Key, again.Operation.ID, got, orig.Operation.ID, want)
		}
	}

	t.Run("a tag change keeps the record", func(t *testing.T) {
		vol := newVol(t, "vol-tags")
		attach(t, "att-tags", vol, first, "/dev/sdf")
		m := mut("det-tags")
		req := resource.DetachVolumeRequest{VolumeID: vol, InstanceID: first}
		orig := detach(t, m, req)
		if _, err := set.Compute.CreateTags(ctx, mut("tag"), resource.CreateTagsRequest{
			IDs: []resource.InstanceID{first}, Tags: map[string]string{"team": "storage"},
		}); err != nil {
			t.Fatal(err)
		}
		replays(t, "after CreateTags", m, req, orig)
		other := m
		other.Fingerprint = "fp-dr-other"
		if _, err := set.Compute.DetachVolume(ctx, other, req); resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
			t.Fatalf("same token, other parameters: %v", err)
		}
	})

	t.Run("a stop and a start keep the record", func(t *testing.T) {
		vol := newVol(t, "vol-power")
		attach(t, "att-power", vol, second, "/dev/sdg")
		m := mut("det-power")
		req := resource.DetachVolumeRequest{VolumeID: vol, InstanceID: second}
		orig := detach(t, m, req)
		if _, err := set.Compute.StopInstances(ctx, mut("stop"), resource.StopInstancesRequest{
			IDs: []resource.InstanceID{second},
		}); err != nil {
			t.Fatal(err)
		}
		replays(t, "after StopInstances", m, req, orig)
		if _, err := set.Compute.StartInstances(ctx, mut("start"), resource.StartInstancesRequest{
			IDs: []resource.InstanceID{second},
		}); err != nil {
			t.Fatal(err)
		}
		replays(t, "after StartInstances", m, req, orig)
	})

	t.Run("a volume-only retry finds its own record", func(t *testing.T) {
		// The older record sits on the instance listed first, so a scan that
		// stops at the first record for the volume finds the wrong one.
		vol := newVol(t, "vol-move")
		attach(t, "att-move-1", vol, first, "/dev/sdh")
		mOld := mut("det-move-1")
		reqOld := resource.DetachVolumeRequest{VolumeID: vol, InstanceID: first}
		old := detach(t, mOld, reqOld)
		attach(t, "att-move-2", vol, second, "/dev/sdh")
		mNew := mut("det-move-2")
		reqNew := resource.DetachVolumeRequest{VolumeID: vol}
		latest := detach(t, mNew, reqNew)
		if latest.Items[0].InstanceID != second || latest.Operation.ID == old.Operation.ID {
			t.Fatalf("second detach %+v op %s", latest.Items[0], latest.Operation.ID)
		}
		replays(t, "newer token, volume only", mNew, reqNew, latest)
		replays(t, "older token", mOld, reqOld, old)
	})

	t.Run("a retry after a reattach returns the first detach", func(t *testing.T) {
		vol := newVol(t, "vol-again")
		attach(t, "att-again-1", vol, first, "/dev/sdi")
		m := mut("det-again-1")
		req := resource.DetachVolumeRequest{VolumeID: vol, InstanceID: first, Device: "/dev/sdi"}
		orig := detach(t, m, req)
		attach(t, "att-again-2", vol, first, "/dev/sdi")
		replays(t, "after reattach", m, req, orig)
		page, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{
			IDs: []resource.VolumeID{vol}, Page: resource.PageRequest{Size: 50},
		})
		if err != nil || len(page.Items) != 1 || page.Items[0].State != resource.VolumeInUse ||
			page.Items[0].InstanceID != first {
			t.Fatalf("the retry must not detach again: %v %+v", err, page.Items)
		}
		mNext := mut("det-again-2")
		next := detach(t, mNext, req)
		if next.Operation.ID == orig.Operation.ID {
			t.Fatalf("a new token got the old detach %s", next.Operation.ID)
		}
		replays(t, "new token after reattach", mNext, req, next)
	})
}

// detachInstances launches two instances and returns them in list order.
func detachInstances(
	ctx context.Context, t *testing.T, set backend.Set, scope backend.Scope, mut func(string) backend.Mutation,
) (resource.InstanceID, resource.InstanceID) {
	t.Helper()
	img, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	sub, err := set.Network.CreateSubnet(ctx, mut("subnet"), resource.CreateSubnetRequest{Cidr: "10.9.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[resource.InstanceID]bool{}
	for _, key := range []string{"run-1", "run-2"} {
		run, err := set.Compute.RunInstances(ctx, mut(key), resource.RunInstancesRequest{
			ImageID: img, InstanceType: "vws.small", SubnetID: sub.Items[0].ID, Count: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		// Polling the launch settles it, as a caller would.
		if _, err := set.Compute.GetOperation(ctx, scope, run.Operation.ID); err != nil {
			t.Fatal(err)
		}
		ids[run.Items[0].ID] = true
	}
	page, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{Page: resource.PageRequest{Size: 50}})
	if err != nil {
		t.Fatal(err)
	}
	var listed []resource.InstanceID
	for _, inst := range page.Items {
		if ids[inst.ID] {
			if inst.State != resource.InstanceRunning {
				t.Fatalf("instance %s is %s, want running", inst.ID, inst.State)
			}
			listed = append(listed, inst.ID)
		}
	}
	if len(listed) != 2 {
		t.Fatalf("listed %v, want both launched instances", listed)
	}
	return listed[0], listed[1]
}
