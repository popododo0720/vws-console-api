package proxmox

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func attachmentMutation(key string) backend.Mutation {
	m := volumeMutation()
	m.Key = fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
	m.Fingerprint = fmt.Sprintf("%x", sha256.Sum256([]byte("fingerprint-"+key)))
	return m
}

func attachmentInstance(t *testing.T, b *Backend) resource.InstanceID {
	t.Helper()
	id := powerID(t)
	_, err := b.StopInstances(t.Context(), attachmentMutation("stop"),
		resource.StopInstancesRequest{IDs: []resource.InstanceID{id}, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func attachmentVolume(t *testing.T, b *Backend, key string) resource.VolumeID {
	t.Helper()
	acc, err := b.CreateVolume(t.Context(), attachmentMutation(key), resource.CreateVolumeRequest{
		SizeGiB: 1, Zone: "pve-test-1a", Tags: map[string]string{"Name": key},
	})
	if err != nil {
		t.Fatal(err)
	}
	return acc.Items[0].ID
}

func reopenedAttachments(t *testing.T, b *Backend) *Backend {
	t.Helper()
	fresh, err := New(t.Context(), b.client, registration(), b.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return fresh
}

func TestAttachDetachSerialTagsAndRestartReplay(t *testing.T) {
	var moves atomic.Int32
	b, _ := volumeWorld(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/move_disk") {
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("delete") != "1" || r.Form.Get("digest") == "" ||
				r.Form.Get("target-digest") == "" || r.Form.Get("target-vmid") == "" {
				t.Errorf("unsafe reassign: %v", r.Form)
			}
			moves.Add(1)
		}
		return false
	})
	inst := attachmentInstance(t, b)
	vol := attachmentVolume(t, b, "serial-tags")
	for _, device := range []string{"/dev/sdf", "/dev/sdz"} {
		req := resource.AttachVolumeRequest{VolumeID: vol, InstanceID: inst, Device: device}
		acc, err := b.AttachVolume(t.Context(), attachmentMutation("attach-"+device), req)
		if err != nil || acc.Items[0].ID != vol || acc.Items[0].Tags["Name"] != "serial-tags" {
			t.Fatalf("attach: %+v %v", acc, err)
		}
		cfg, err := b.client.VMConfig(t.Context(), pveclient.VM{Node: "pve1", VMID: 100})
		slot, slotErr := attachmentSlot(device)
		if err != nil || slotErr != nil || option(cfg.Drives[slot], "serial") != strings.TrimPrefix(vol.String(), "vol-") {
			t.Fatalf("mapped device %s: %+v %v %v", device, cfg, err, slotErr)
		}
		for range 2 {
			fresh := reopenedAttachments(t, b)
			if _, err := fresh.AttachVolume(t.Context(), attachmentMutation("attach-"+device), req); err != nil {
				t.Fatal(err)
			}
		}
		m := attachmentMutation("detach-" + device)
		detReq := resource.DetachVolumeRequest{VolumeID: vol}
		first, err := b.DetachVolume(t.Context(), m, detReq)
		if err != nil || first.Items[0].Device != device || first.Items[0].InstanceID != inst {
			t.Fatalf("detach: %+v %v", first, err)
		}
		if _, err := b.GetOperation(t.Context(), m.Scope, first.Operation.ID); err != nil {
			t.Fatal(err)
		}
		page, err := b.DescribeVolumes(t.Context(), m.Scope, resource.VolumeQuery{IDs: []resource.VolumeID{vol}})
		if err != nil || page.Items[0].State != resource.VolumeAvailable || page.Items[0].Tags["Name"] != "serial-tags" {
			t.Fatalf("available: %+v %v", page, err)
		}
		if _, err := b.AttachVolume(t.Context(), attachmentMutation("reattach-"+device), req); err != nil {
			t.Fatal(err)
		}
		before := moves.Load()
		again, err := reopenedAttachments(t, b).DetachVolume(t.Context(), m, detReq)
		if err != nil || !reflect.DeepEqual(first, again) || moves.Load() != before {
			t.Fatalf("replay changed original result or attachment: %+v %v", again, err)
		}
		m.Fingerprint = "different"
		if _, err := b.DetachVolume(t.Context(), m, detReq); resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
			t.Fatalf("changed fingerprint: %v", err)
		}
		m = attachmentMutation("cleanup-" + device)
		m.MintedToken = true
		if _, err := b.DetachVolume(t.Context(), m, detReq); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDetachReplayBudgetWindowAndMinted(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprintf("pending=%t", pending), func(t *testing.T) {
			b, _ := volumeWorld(t, nil)
			inst := attachmentInstance(t, b)
			for i := range backend.MaxDetachReplays + 1 {
				vol := attachmentVolume(t, b, fmt.Sprintf("budget-%d", i))
				if _, err := b.AttachVolume(t.Context(), attachmentMutation(fmt.Sprintf("attach-%d", i)),
					resource.AttachVolumeRequest{VolumeID: vol, InstanceID: inst, Device: "/dev/sdf"}); err != nil {
					t.Fatal(err)
				}
				m := attachmentMutation(fmt.Sprintf("detach-%d", i))
				_, err := b.DetachVolume(t.Context(), m, resource.DetachVolumeRequest{VolumeID: vol})
				if i < backend.MaxDetachReplays {
					if err != nil {
						t.Fatal(err)
					}
					continue
				}
				if resource.CodeOf(err) != resource.CodeResourceExhausted {
					t.Fatalf("fifth detach: %v", err)
				}
				m.MintedToken = true
				if _, err := b.DetachVolume(t.Context(), m, resource.DetachVolumeRequest{VolumeID: vol}); err != nil {
					t.Fatal(err)
				}
				vm := pveclient.VM{Node: "pve1", VMID: 100}
				cfg, err := b.client.VMConfig(t.Context(), vm)
				if err != nil {
					t.Fatal(err)
				}
				records, _, err := detachRecords(cfg.Description)
				if err != nil || len(records) != backend.MaxDetachReplays ||
					strings.Count(cfg.Tags, "vws.d.") != backend.MaxDetachReplays {
					t.Fatalf("minted token changed budget: %+v %v", records, err)
				}
				for j := range records {
					records[j].At = time.Now().Add(-backend.ClientTokenWindow - 2*backend.ClientTokenGrace).Unix()
					records[j].Pending = pending
				}
				records[0].Item.VolumeID = vol
				if err := b.saveDetaches(t.Context(), vm, cfg, records); err != nil {
					t.Fatal(err)
				}
				if _, err := b.AttachVolume(t.Context(), attachmentMutation("window-attach"),
					resource.AttachVolumeRequest{VolumeID: vol, InstanceID: inst, Device: "/dev/sdf"}); err != nil {
					t.Fatal(err)
				}
				m.MintedToken = false
				fresh := reopenedAttachments(t, b)
				if _, err := fresh.DetachVolume(t.Context(), m, resource.DetachVolumeRequest{VolumeID: vol}); err != nil {
					t.Fatalf("expired records held the budget: %v", err)
				}
			}
		})
	}
}

func TestAttachDetachRecoverAfterMoveBeforeTagCleanup(t *testing.T) {
	var armed, moved atomic.Bool
	b, f := volumeWorld(t, func(w http.ResponseWriter, r *http.Request) bool {
		if armed.Load() && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/move_disk") {
			moved.Store(true)
		}
		if moved.Load() && r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/config") && armed.Swap(false) {
			moved.Store(false)
			http.Error(w, `{"message":"interrupted tag cleanup"}`, http.StatusInternalServerError)
			return true
		}
		return false
	})
	inst := attachmentInstance(t, b)
	vol := attachmentVolume(t, b, "interrupted")
	req := resource.AttachVolumeRequest{VolumeID: vol, InstanceID: inst, Device: "/dev/sdf"}
	armed.Store(true)
	if _, err := b.AttachVolume(t.Context(), attachmentMutation("attach-interrupted"), req); err == nil {
		t.Fatal("lost source tag cleanup error")
	}
	b = reopenedAttachments(t, b)
	if _, err := b.AttachVolume(t.Context(), attachmentMutation("attach-interrupted"), req); err != nil {
		t.Fatal(err)
	}
	m := attachmentMutation("detach-interrupted")
	armed.Store(true)
	if _, err := b.DetachVolume(t.Context(), m, resource.DetachVolumeRequest{VolumeID: vol}); err == nil {
		t.Fatal("lost detach cleanup error")
	}
	b = reopenedAttachments(t, b)
	got, err := b.DetachVolume(t.Context(), m, resource.DetachVolumeRequest{VolumeID: vol})
	if err != nil || got.Items[0].VolumeID != vol {
		t.Fatalf("resume: %+v %v", got, err)
	}
	if _, err := b.AttachVolume(t.Context(), attachmentMutation("task-retry"), req); err != nil {
		t.Fatal(err)
	}
	f.FailNext("qmmove", "injected move failure")
	m = attachmentMutation("failed-detach")
	if _, err := b.DetachVolume(t.Context(), m, resource.DetachVolumeRequest{VolumeID: vol}); err == nil {
		t.Fatal("lost task failure")
	}
	fresh := reopenedAttachments(t, b)
	if _, err := fresh.DetachVolume(t.Context(), m, resource.DetachVolumeRequest{VolumeID: vol}); err != nil {
		t.Fatal(err)
	}
	t.Run("minted detach discards stale destination tags", func(t *testing.T) {
		if _, err := b.AttachVolume(t.Context(), attachmentMutation("minted-attach"), req); err != nil {
			t.Fatal(err)
		}
		m.MintedToken = true
		armed.Store(true)
		if _, err := b.DetachVolume(t.Context(), m, resource.DetachVolumeRequest{VolumeID: vol}); err == nil {
			t.Fatal("lost minted detach cleanup error")
		}
		if _, err := b.UntagVolumes(t.Context(), m, resource.UntagVolumesRequest{
			IDs: []resource.VolumeID{vol}, Tags: []resource.TagSelector{{Key: "Name"}},
		}); err != nil {
			t.Fatal(err)
		}
		acc, err := reopenedAttachments(t, b).AttachVolume(t.Context(), attachmentMutation("fresh-tags"), req)
		if err != nil || len(acc.Items[0].Tags) != 0 {
			t.Fatalf("stale destination tags returned: %+v %v", acc, err)
		}
	})
}

func TestDetachSkipsCorruptUnrelatedReplay(t *testing.T) {
	b, f := volumeWorld(t, nil)
	inst := attachmentInstance(t, b)
	vol := attachmentVolume(t, b, "corrupt-replay")
	req := resource.AttachVolumeRequest{VolumeID: vol, InstanceID: inst, Device: "/dev/sdf"}
	if _, err := b.AttachVolume(t.Context(), attachmentMutation("attach"), req); err != nil {
		t.Fatal(err)
	}
	m := attachmentMutation("corrupt")
	key := sha256.Sum256([]byte(m.Key))
	if err := b.client.VolumeWrite(t.Context(), http.MethodPost, "/nodes/pve1/qemu", url.Values{
		"vmid": {"200"}, "pool": {"tenant_pool"}, "description": {"vws:detach invalid"},
		"tags": {fmt.Sprintf("vws.d.%x.bad.1", key[8:16])},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.DetachVolume(t.Context(), m, resource.DetachVolumeRequest{VolumeID: vol}); err != nil {
		t.Fatalf("unrelated corrupt replay blocked detach: %v", err)
	}
	if _, err := b.AttachVolume(t.Context(), attachmentMutation("reattach"), req); err != nil {
		t.Fatal(err)
	}
	vm := pveclient.VM{Node: "pve1", VMID: 100}
	cfg, err := b.client.VMConfig(t.Context(), vm)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.client.WriteConfigTags(t.Context(), vm, cfg.Digest, cfg.Tags, "vws:detach invalid"); err != nil {
		t.Fatal(err)
	}
	before := len(f.Requests())
	var rerr *resource.Error
	if _, err := b.DetachVolume(t.Context(), m, resource.DetachVolumeRequest{VolumeID: vol}); !errors.As(err, &rerr) ||
		rerr.Code != resource.CodeUnavailable {
		t.Fatalf("matched corrupt replay: %v, want Unavailable", err)
	}
	for _, call := range f.Requests()[before:] {
		if !strings.HasPrefix(call, "GET ") {
			t.Fatalf("corrupt target replay wrote %s", call)
		}
	}
}

func TestAttachDetachBoundaryPoolsAndRunning(t *testing.T) {
	b, f := volumeWorld(t, nil)
	inst := attachmentInstance(t, b)
	vol := attachmentVolume(t, b, "boundary")
	req := resource.AttachVolumeRequest{VolumeID: vol, InstanceID: inst, Device: "/dev/sdf"}
	for _, device := range []string{"", "/dev/sda", "/dev/sde", "/dev/sdf1", "../scsi1", "/dev/sdzz"} {
		req.Device = device
		_, err := b.AttachVolume(t.Context(), attachmentMutation(device), req)
		if resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Fatalf("device %q: %v", device, err)
		}
	}
	req.Device = "/dev/sdf"
	holder, _, _, err := b.volumeDrive(t.Context(), inventoryScope(), vol)
	if err != nil {
		t.Fatal(err)
	}
	for _, vm := range []int{holder.VMID, 100} {
		if err := f.MoveVM(vm, "foreign"); err != nil {
			t.Fatal(err)
		}
		before := len(f.Requests())
		_, err := b.AttachVolume(t.Context(), attachmentMutation("foreign"), req)
		kind, id := resource.KindVolume, vol.String()
		if vm == 100 {
			kind, id = resource.KindInstance, inst.String()
		}
		assertMutationNotFound(t, err, kind, id)
		for _, call := range f.Requests()[before:] {
			if !strings.HasPrefix(call, "GET ") {
				t.Fatalf("foreign pool wrote %s", call)
			}
		}
		if err := f.MoveVM(vm, "tenant_pool"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.AttachVolume(t.Context(), attachmentMutation("valid"), req); err != nil {
		t.Fatal(err)
	}
	req.Device = "/dev/sdg"
	_, err = b.AttachVolume(t.Context(), attachmentMutation("in-use"), req)
	if resource.CodeOf(err) != resource.CodeConflict {
		t.Fatalf("in-use volume: %v", err)
	}
	_, err = b.StartInstances(t.Context(), attachmentMutation("start"),
		resource.StartInstancesRequest{IDs: []resource.InstanceID{inst}})
	if err != nil {
		t.Fatal(err)
	}
	vm := pveclient.VM{Node: "pve1", VMID: 100}
	cfg, err := b.client.VMConfig(t.Context(), vm)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.client.VolumeWrite(t.Context(), http.MethodPut, volumeVMPath(vm)+"/config",
		url.Values{"delete": {"scsi1"}, "digest": {cfg.Digest}}, nil); err == nil {
		t.Fatal("fake unexpectedly modeled config hot-unplug to unused")
	}
	before := len(f.Requests())
	_, err = b.DetachVolume(t.Context(), attachmentMutation("running"), resource.DetachVolumeRequest{VolumeID: vol})
	if resource.CodeOf(err) != resource.CodeConflict || resource.AsError(err).Kind != resource.KindVolume {
		t.Fatalf("running detach: %v", err)
	}
	for _, call := range f.Requests()[before:] {
		if !strings.HasPrefix(call, "GET ") {
			t.Fatalf("running detach wrote %s", call)
		}
	}
	caps, err := b.RegionCapabilities(t.Context(), b.region)
	if err != nil || caps.Actions["ec2:AttachVolume"].State != resource.ActionSupported ||
		caps.Actions["ec2:DetachVolume"].State != resource.ActionPartial ||
		caps.Actions["ec2:DetachVolume"].ReasonCode != "StoppedInstance" {
		t.Fatalf("capabilities: %+v %v", caps, err)
	}
}

func TestDetachDescriptionBounds(t *testing.T) {
	for _, text := range []string{
		"vws:detach {}\nvws:detach []", "vws:detach invalid",
		"vws:detach [{},{},{},{},{}]", "vws:detach [{}]",
	} {
		if _, _, err := detachRecords(text); err == nil {
			t.Fatalf("accepted malformed replay block %q", text)
		}
	}
	b := &Backend{}
	cfg := pveclient.VMConfig{Description: strings.Repeat("x", 8193)}
	if err := b.saveDetaches(t.Context(), pveclient.VM{}, cfg, nil); err == nil {
		t.Fatal("oversized description was written")
	}
	_, kept, err := detachRecords("operator text\nvws:tags {\"Name\":\"instance\"}\nvws:detach []")
	if err != nil || kept != "operator text\nvws:tags {\"Name\":\"instance\"}" {
		t.Fatalf("operator text or user tags changed: %q %v", kept, err)
	}
}
