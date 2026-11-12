package proxmox

import (
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func volumeWorld(t *testing.T, intercept func(http.ResponseWriter, *http.Request) bool) (*Backend, *pvefake.Fake) {
	t.Helper()
	s := inventoryScenario()
	s.VMs[0].Pool = "tenant_pool"
	s.Pools = []string{"tenant_pool"}
	s.Roles = append(s.Roles, pvefake.Role{
		ID:    "Volumes",
		Privs: []string{"Pool.Audit", "VM.Audit", "VM.Allocate", "VM.Config.Disk", "VM.Config.Options", "VM.PowerMgmt"},
	},
		pvefake.Role{ID: "Allocate", Privs: []string{"Datastore.Audit", "Datastore.AllocateSpace"}})
	s.Tokens[0].ACL = append(s.Tokens[0].ACL,
		pvefake.ACE{Path: "/pool/tenant_pool", Role: "Volumes"},
		pvefake.ACE{Path: "/storage/local", Role: "Allocate"})
	f, err := pvefake.New(s)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if intercept == nil || !intercept(w, r) {
			f.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		if violations := f.PoolWriteViolations(); len(violations) != 0 {
			t.Fatal(violations)
		}
	})
	client, err := pveclient.New(pveclient.Config{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
		TokenID: s.Tokens[0].ID, Secret: pveclient.Secret(s.Tokens[0].Secret), PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(t.Context(), client, registration(), RegionConfig{
		Pools:    map[string]string{"123456789012": "tenant_pool"},
		Storages: map[string]string{"gp2": "local"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b, f
}

func volumeMutation() backend.Mutation {
	return backend.Mutation{Scope: inventoryScope(), Key: strings.Repeat("a", 64), Fingerprint: strings.Repeat("b", 64)}
}

func TestVolumeHolderCreateRetryRestartDelete(t *testing.T) {
	var creates atomic.Int32
	b, f := volumeWorld(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/pve1/qemu" {
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("start") != "0" || r.Form.Get("description") != holderDescription ||
				r.Form.Get("tags") != "vws.holder" || r.Form.Get("name") != "vws-holder" {
				t.Errorf("unsafe holder creation: %v", r.Form)
			}
			creates.Add(1)
		}
		return false
	})
	m := volumeMutation()
	req := resource.CreateVolumeRequest{SizeGiB: 8, Zone: "pve-test-1a", Tags: map[string]string{"Name": "data"}}
	got, err := b.CreateVolume(t.Context(), m, req)
	if err != nil || len(got.Items) != 1 || got.Operation.State != resource.OperationSucceeded {
		t.Fatalf("create=%+v error=%v", got, err)
	}
	if _, err := decodeOperation(got.Operation.ID); err != nil {
		t.Fatal(err)
	}
	number, _ := new(big.Int).SetString(strings.TrimPrefix(got.Items[0].ID.String(), "vol-"), 16)
	content, err := b.client.StorageContent(t.Context(), "pve1", "local")
	if err != nil || len(content) != 1 ||
		!strings.HasSuffix(content[0].VolID, "-disk-"+number.String()+".raw") {
		t.Fatalf("allocation filename must preserve all 68 serial bits: %+v %v", content, err)
	}
	fresh, err := New(t.Context(), b.client, registration(), b.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		retry, err := fresh.CreateVolume(t.Context(), m, req)
		if err != nil || retry.Items[0].ID != got.Items[0].ID || retry.Operation.ID != got.Operation.ID {
			t.Fatalf("retry=%+v error=%v", retry, err)
		}
	}
	if creates.Load() != 1 {
		t.Fatalf("created %d holders", creates.Load())
	}
	page, err := fresh.DescribeVolumes(t.Context(), m.Scope, resource.VolumeQuery{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Tags["Name"] != "data" ||
		page.Items[0].State != resource.VolumeAvailable {
		t.Fatalf("inventory=%+v error=%v", page, err)
	}
	req.SizeGiB++
	if _, err := fresh.CreateVolume(t.Context(), m, req); resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
		t.Fatalf("changed size: %v", err)
	}
	instances, err := fresh.DescribeInstances(t.Context(), m.Scope, resource.InstanceQuery{})
	if err != nil || len(instances.Items) != 1 {
		t.Fatalf("holder leaked into instances: %+v %v", instances, err)
	}
	vm, _, _, err := fresh.volumeDrive(t.Context(), m.Scope, got.Items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range f.Requests() {
		if strings.Contains(request, "/qemu/") && strings.Contains(request, "/status/") {
			t.Fatalf("backend powered the holder: %s", request)
		}
	}
	for _, action := range []string{"start", "reboot"} {
		path := volumeVMPath(vm) + "/status/" + action
		if err := b.client.VolumeWrite(t.Context(), http.MethodPost, path, nil, nil); err == nil {
			t.Fatalf("holder accepted %s", action)
		}
	}
	deleted, err := fresh.DeleteVolume(t.Context(), m, resource.DeleteVolumeRequest{ID: got.Items[0].ID})
	if err != nil || deleted.Operation.State != resource.OperationSucceeded {
		t.Fatalf("delete=%+v error=%v", deleted, err)
	}
	if _, err := fresh.DescribeVolumes(t.Context(), m.Scope,
		resource.VolumeQuery{IDs: []resource.VolumeID{got.Items[0].ID}}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("disk survived unlink: %v", err)
	}
	cfg, err := fresh.client.VMConfig(t.Context(), vm)
	if err != nil || cfg.Tags != "vws.holder" {
		t.Fatalf("deleted volume left tags behind: %+v %v", cfg, err)
	}
	t.Log("holder start=0; restart and token replay preserved one volume; changed size mismatched; unlink removed disk")
}

func TestVolumeCreateRecoversAllocationAfterConfigFailure(t *testing.T) {
	var fail, unlinkFail, unreadable atomic.Bool
	fail.Store(true)
	b, _ := volumeWorld(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/config") &&
			(strings.HasSuffix(r.URL.Path, "/qemu/100/config") || unreadable.Load()) {
			w.WriteHeader(http.StatusForbidden)
			return true
		}
		if r.Method == http.MethodPut && ((strings.HasSuffix(r.URL.Path, "/config") && fail.Swap(false)) ||
			(strings.HasSuffix(r.URL.Path, "/unlink") && unlinkFail.Swap(false))) {
			w.WriteHeader(http.StatusInternalServerError)
			if err := json.NewEncoder(w).Encode(map[string]string{"message": "injected config outage"}); err != nil {
				t.Error(err)
			}
			return true
		}
		return false
	})
	req := resource.CreateVolumeRequest{SizeGiB: 2, Zone: "pve-test-1a", Tags: map[string]string{"Name": "recovery"}}
	if _, err := b.CreateVolume(t.Context(), volumeMutation(), req); err == nil {
		t.Fatal("config failure disappeared")
	}
	fresh, err := New(t.Context(), b.client, registration(), b.cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := fresh.CreateVolume(t.Context(), volumeMutation(), req)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := b.client.StorageContent(t.Context(), "pve1", "local")
	if err != nil || len(rows) != 1 {
		t.Fatalf("allocation duplicated after restart: %+v %v", rows, err)
	}
	unreadable.Store(true)
	_, _, _, err = fresh.volumeDrive(t.Context(), inventoryScope(), got.Items[0].ID)
	if err == nil || resource.CodeOf(err) == resource.CodeNotFound {
		t.Fatalf("unreadable holder became NotFound: %v", err)
	}
	unreadable.Store(false)
	del := resource.DeleteVolumeRequest{ID: got.Items[0].ID}
	for _, failure := range []*atomic.Bool{&unlinkFail, &fail} {
		failure.Store(true)
		if _, err := fresh.DeleteVolume(t.Context(), volumeMutation(), del); err == nil {
			t.Fatal("delete ignored injected failure")
		}
		page, err := fresh.DescribeVolumes(t.Context(), inventoryScope(),
			resource.VolumeQuery{IDs: []resource.VolumeID{del.ID}})
		if err != nil || page.Items[0].Tags["Name"] != "recovery" {
			t.Fatalf("failed delete removed the disk or tags: %+v %v", page, err)
		}
	}
	if _, err := fresh.DeleteVolume(t.Context(), volumeMutation(), del); err != nil {
		t.Fatal(err)
	}
	_, err = fresh.DeleteVolume(t.Context(), volumeMutation(), del)
	assertMutationNotFound(t, err, resource.KindVolume, del.ID.String())
	t.Log("restart recovered the allocated image after a failed config write without allocating a duplicate")
}

func TestVolumeWriteRefusals(t *testing.T) {
	b, f := volumeWorld(t, nil)
	m := volumeMutation()
	for _, req := range []resource.CreateVolumeRequest{
		{SizeGiB: -1},
		{SizeGiB: 1, Zone: "../../outside"},
		{SizeGiB: 1, Tags: map[string]string{"vws:holder": "bad"}},
	} {
		before := len(f.Requests())
		if _, err := b.CreateVolume(t.Context(), m, req); resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Fatalf("invalid create %+v: %v", req, err)
		}
		for _, request := range f.Requests()[before:] {
			if !strings.HasPrefix(request, "GET ") {
				t.Fatalf("invalid create wrote: %s", request)
			}
		}
	}
	sid, _ := resource.Parse[resource.SnapshotID]("snap-0123456789abcdef0")
	_, err := b.CreateVolume(t.Context(), m, resource.CreateVolumeRequest{SnapshotID: sid})
	if !resource.IsUnsupported(resource.AsError(err)) {
		t.Fatalf("snapshot source: %v", err)
	}
	caps, err := b.RegionCapabilities(t.Context(), b.region)
	if err != nil || caps.Actions["ec2:CreateVolume"].State != resource.ActionPartial ||
		caps.Actions["ec2:CreateVolume"].Reason == "" {
		t.Fatalf("capability=%+v error=%v", caps, err)
	}
	b.cfg.ReadOnly = true
	_, err = b.CreateVolume(t.Context(), m, resource.CreateVolumeRequest{SizeGiB: 1})
	if !resource.IsUnsupported(resource.AsError(err)) {
		t.Fatalf("read-only create: %v", err)
	}
}

func TestVolumeDeleteInUseAndForeignPool(t *testing.T) {
	b, f := volumeWorld(t, nil)
	m := volumeMutation()
	vm := pveclient.VM{Node: "pve1", VMID: 100}
	var volid string
	if err := b.client.VolumeWrite(t.Context(), http.MethodPost, "/nodes/pve1/storage/local/content",
		url.Values{"vmid": {"100"}, "filename": {"vm-100-disk-0"}, "size": {"8G"}}, &volid); err != nil {
		t.Fatal(err)
	}
	cfg, err := b.client.VMConfig(t.Context(), vm)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.client.VolumeWrite(t.Context(), http.MethodPut, volumeVMPath(vm)+"/config",
		url.Values{"scsi0": {volid + ",serial=0123456789abcdef0"}, "digest": {cfg.Digest}}, nil); err != nil {
		t.Fatal(err)
	}
	id, _ := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
	_, _, _, err = b.volumeDrive(t.Context(), m.Scope, id)
	assertMutationNotFound(t, err, resource.KindVolume, id.String())
	if _, err := b.DeleteVolume(t.Context(), m, resource.DeleteVolumeRequest{ID: id}); err == nil ||
		err.Error() != resource.VolumeAttached(id).Error() {
		t.Fatalf("in-use delete: %v", err)
	}
	if err := f.MoveVM(100, "foreign"); err != nil {
		t.Fatal(err)
	}
	before := len(f.Requests())
	_, err = b.DeleteVolume(t.Context(), m, resource.DeleteVolumeRequest{ID: id})
	assertMutationNotFound(t, err, resource.KindVolume, id.String())
	for _, request := range f.Requests()[before:] {
		if !strings.HasPrefix(request, "GET ") {
			t.Fatalf("cross-pool delete wrote: %s", request)
		}
	}
	t.Log("in-use deletion returned VolumeInUse; a pool move denied deletion before any write")
}
