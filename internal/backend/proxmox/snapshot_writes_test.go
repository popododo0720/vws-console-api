package proxmox

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func snapshotWriteScenario() pvefake.Scenario {
	s := mutationScenario()
	s.Roles = append(s.Roles, pvefake.Role{ID: "SnapshotWriter", Privs: []string{"VM.Snapshot", "Pool.Audit"}})
	s.Tokens[0].ACL = append(s.Tokens[0].ACL,
		pvefake.ACE{Path: "/pool/123456789012", Role: "SnapshotWriter"})
	return s
}

func snapshotWriteBackend(t *testing.T, s pvefake.Scenario, cfg RegionConfig) (*Backend, *pvefake.Fake) {
	t.Helper()
	f, err := pvefake.New(s)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := pveclient.New(pveclient.Config{
		BaseURL: srv.URL, TokenID: s.Tokens[0].ID, Secret: pveclient.Secret(s.Tokens[0].Secret),
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(t.Context(), c, registration(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if writes := f.PoolWriteViolations(); len(writes) != 0 {
			t.Fatalf("forbidden pool writes: %v", writes)
		}
	})
	return b, f
}

func TestSnapshotWritesRestartReplay(t *testing.T) {
	for _, holder := range []bool{false, true} {
		t.Run(fmt.Sprintf("holder=%v", holder), func(t *testing.T) {
			s := snapshotWriteScenario()
			if holder {
				s.VMs[0].Tags = "vws.holder"
			}
			s.VMs[0].Config["scsi1"] = "local:vm-100-disk-1,serial=1123456789abcdef0"
			s.Storages[0].Content = append(s.Storages[0].Content, pvefake.StorageContent{
				VolID: "local:vm-100-disk-1", Content: "images", Size: 12 << 30, VMID: 100,
			})
			initial, f := snapshotWriteBackend(t, s, RegionConfig{})
			c := initial.client
			reopen := func() *Backend {
				b, err := New(t.Context(), c, registration(), RegionConfig{})
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			m := backend.Mutation{Scope: inventoryScope(), Key: "snapshot-token", Fingerprint: strings.Repeat("a", 64)}
			vid, _ := resource.Parse[resource.VolumeID]("vol-1123456789abcdef0")
			req := resource.CreateSnapshotRequest{
				VolumeID: vid, Description: "daily & backup\noperator note",
				Tags: map[string]string{"Name": "backup", strings.Repeat("k", 128): "value"},
			}
			ids, _ := NewIDs("test")
			hash := sha256.Sum256([]byte(m.Key))
			name := fmt.Sprintf("vws-%x", hash[:8])
			want, _ := ids.Snapshot(configUUID(pveclient.VMConfig{SMBIOS1: s.VMs[0].Config["smbios1"]}), name)
			accepted, err := reopen().CreateSnapshot(t.Context(), m, req)
			if err != nil || len(accepted.Items) != 1 || accepted.Items[0].ID != want ||
				accepted.Items[0].VolumeID != vid || accepted.Items[0].VolumeSize != 12 {
				t.Fatalf("create=%+v error=%v", accepted, err)
			}
			op, err := decodeOperation(accepted.Operation.ID)
			if err != nil {
				t.Fatal(err)
			}
			stable, ok := op.(syncOperation)
			if !ok || stable.action != resource.ActionCreateSnapshot || stable.kind != resource.KindSnapshot {
				t.Fatalf("snapshot operation does not decode to stable reference: %+v", op)
			}
			before := len(f.Requests())
			for range 2 {
				retry, err := reopen().CreateSnapshot(t.Context(), m, req)
				if err != nil || retry.Items[0].ID != want || retry.Operation.ID != accepted.Operation.ID {
					t.Fatalf("restart replay=%+v error=%v", retry, err)
				}
			}
			m.Fingerprint = strings.Repeat("b", 64)
			if _, err := reopen().CreateSnapshot(t.Context(), m, req); resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
				t.Fatalf("changed fingerprint=%v", err)
			}
			for _, request := range f.Requests()[before:] {
				if !strings.HasPrefix(request, "GET ") {
					t.Fatalf("replay wrote PVE: %s", request)
				}
			}
			query := resource.SnapshotQuery{IDs: []resource.SnapshotID{want}}
			page, err := reopen().DescribeSnapshots(t.Context(), m.Scope, query)
			if err != nil || len(page.Items) != 1 || page.Items[0].VolumeID != vid ||
				page.Items[0].VolumeSize != 12 || page.Items[0].Tags["Name"] != "backup" {
				t.Fatalf("snapshot read=%+v error=%v", page, err)
			}
			rows, err := c.Snapshots(t.Context(), pveclient.VM{Node: "pve1", VMID: 100})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, row := range rows {
				if row.Name == name {
					found = true
					if row.VMState != 0 || !strings.HasPrefix(row.Description,
						"vws:fp="+strings.Repeat("a", 16)+" vws:vol=1123456789abcdef0\n") {
						t.Fatalf("snapshot marker=%+v", row)
					}
				}
			}
			if !found {
				t.Fatal("snapshot not persisted in PVE")
			}
			for _, request := range f.Requests() {
				if strings.Contains(request, "/rollback") {
					t.Fatalf("rollback called: %s", request)
				}
			}
		})
	}
}

func TestSnapshotWritesRejectUnsafeInputAndForeignPools(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*resource.CreateSnapshotRequest, *backend.Mutation)
	}{
		{"reserved tag", func(r *resource.CreateSnapshotRequest, _ *backend.Mutation) {
			r.Tags = map[string]string{"vws:admin": "true"}
		}},
		{"description bound", func(r *resource.CreateSnapshotRequest, _ *backend.Mutation) {
			r.Description = strings.Repeat("x", 256)
		}},
		{"empty fingerprint", func(_ *resource.CreateSnapshotRequest, m *backend.Mutation) { m.Fingerprint = "" }},
		{"malicious fingerprint", func(_ *resource.CreateSnapshotRequest, m *backend.Mutation) {
			m.Fingerprint = strings.Repeat("a", 16) + "\nvws:vol=bad"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, f := snapshotWriteBackend(t, snapshotWriteScenario(), RegionConfig{})
			vid, _ := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
			req := resource.CreateSnapshotRequest{VolumeID: vid}
			m := backend.Mutation{Scope: inventoryScope(), Key: "key", Fingerprint: strings.Repeat("a", 64)}
			tc.edit(&req, &m)
			before := len(f.Requests())
			if _, err := b.CreateSnapshot(t.Context(), m, req); err == nil {
				t.Fatal("unsafe request accepted")
			}
			for _, request := range f.Requests()[before:] {
				if !strings.HasPrefix(request, "GET ") {
					t.Fatalf("invalid request wrote PVE: %s", request)
				}
			}
		})
	}
	b, f := snapshotWriteBackend(t, snapshotWriteScenario(), RegionConfig{})
	vid, _ := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
	if err := f.MoveVM(100, "foreign"); err != nil {
		t.Fatal(err)
	}
	before := len(f.Requests())
	_, err := b.CreateSnapshot(t.Context(), backend.Mutation{Scope: inventoryScope()},
		resource.CreateSnapshotRequest{VolumeID: vid})
	assertMutationNotFound(t, err, resource.KindVolume, vid.String())
	for _, request := range f.Requests()[before:] {
		if !strings.HasPrefix(request, "GET ") {
			t.Fatalf("foreign request wrote PVE: %s", request)
		}
	}
}

func TestSnapshotWritesReadOnlyAndFailure(t *testing.T) {
	for _, readonly := range []bool{false, true} {
		s := snapshotWriteScenario()
		if readonly {
			s = mutationScenario()
		} else {
			s.Roles[1].Privs = []string{"VM.Audit", "Pool.Audit"}
		}
		b, f := snapshotWriteBackend(t, s, RegionConfig{ReadOnly: readonly})
		vid, _ := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
		m := backend.Mutation{Scope: inventoryScope(), Key: "key", Fingerprint: strings.Repeat("a", 64)}
		before := len(f.Requests())
		_, err := b.CreateSnapshot(t.Context(), m, resource.CreateSnapshotRequest{VolumeID: vid})
		var domain *resource.Error
		if err == nil || readonly && (!errors.As(err, &domain) || !resource.IsUnsupported(domain)) {
			t.Fatalf("readonly=%v error=%v", readonly, err)
		}
		writes := 0
		for _, request := range f.Requests()[before:] {
			if strings.HasPrefix(request, "POST ") {
				writes++
			}
		}
		if readonly && writes != 0 || !readonly && writes != 1 {
			t.Fatalf("readonly=%v writes=%d", readonly, writes)
		}
		caps, err := b.RegionCapabilities(t.Context(), b.region)
		if err != nil {
			t.Fatal(err)
		}
		want := resource.ActionSupported
		if readonly {
			want = resource.ActionUnsupported
		}
		if caps.Actions["ec2:CreateSnapshot"].State != want || caps.Features.SnapshotScope != "vm" {
			t.Fatalf("capability=%+v", caps)
		}
	}
}

func TestSnapshotRollbackIsForbidden(t *testing.T) {
	_, f := snapshotWriteBackend(t, snapshotWriteScenario(), RegionConfig{})
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://pve/api2/json/nodes/pve1/qemu/100/snapshot/daily/rollback", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "PVEAPIToken=vws@pve!inventory=fake-secret")
	w := httptest.NewRecorder()
	f.ServeHTTP(w, request)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "snapshot rollback is forbidden") {
		t.Fatalf("rollback status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestSnapshotWritesRetryWhileTaskRuns(t *testing.T) {
	b, f := snapshotWriteBackend(t, snapshotWriteScenario(), RegionConfig{})
	if err := f.SetTaskDelay(50 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	id, _ := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
	m := backend.Mutation{Scope: inventoryScope(), Key: "pending", Fingerprint: strings.Repeat("a", 64)}
	req := resource.CreateSnapshotRequest{VolumeID: id}
	first, err := b.CreateSnapshot(t.Context(), m, req)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := b.CreateSnapshot(t.Context(), m, req)
	if err != nil || retry.Items[0].ID != first.Items[0].ID || retry.Operation.ID != first.Operation.ID {
		t.Fatalf("pending replay=%+v error=%v", retry, err)
	}
	writes := 0
	for _, request := range f.Requests() {
		if strings.HasPrefix(request, "POST ") {
			writes++
		}
	}
	if writes != 1 {
		t.Fatalf("pending replay submitted %d tasks", writes)
	}
}

func TestSnapshotWritesReplayAfterNewerTasks(t *testing.T) {
	b, f := snapshotWriteBackend(t, snapshotWriteScenario(), RegionConfig{})
	id, _ := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
	m := backend.Mutation{Scope: inventoryScope(), Key: "oldest", Fingerprint: strings.Repeat("a", 64)}
	req := resource.CreateSnapshotRequest{VolumeID: id}
	first, err := b.CreateSnapshot(t.Context(), m, req)
	if err != nil {
		t.Fatal(err)
	}
	for n := range 51 {
		if err := f.SetTaskDelay(time.Duration(n/50) * time.Hour); err != nil {
			t.Fatal(err)
		}
		newer := m
		newer.Key = fmt.Sprintf("newer-%d", n)
		if _, err := b.CreateSnapshot(t.Context(), newer, req); err != nil {
			t.Fatal(err)
		}
	}
	before := len(f.Requests())
	retry, err := b.CreateSnapshot(t.Context(), m, req)
	if err != nil || retry.Operation.ID != first.Operation.ID || retry.Items[0].ID != first.Items[0].ID {
		t.Fatalf("old snapshot replay=%+v error=%v", retry, err)
	}
	op, err := b.GetOperation(t.Context(), m.Scope, first.Operation.ID)
	if err != nil || op.State != resource.OperationSucceeded {
		t.Fatalf("snapshot poll=%+v error=%v", op, err)
	}
	foreign := m.Scope
	foreign.Account, _ = resource.Parse[resource.AccountID]("999999999999")
	_, err = b.GetOperation(t.Context(), foreign, first.Operation.ID)
	assertMutationNotFound(t, err, resource.KindOperation, first.Operation.ID.String())
	for _, request := range f.Requests()[before:] {
		if !strings.HasPrefix(request, "GET ") || strings.Contains(request, "/tasks") {
			t.Fatalf("replay depends on task history or writes PVE: %s", request)
		}
	}
}

func TestSnapshotWritesTokenCannotMoveToAnotherVM(t *testing.T) {
	s := snapshotWriteScenario()
	s.VMs = append(s.VMs, pvefake.VM{
		VMID: 101, Node: "pve1", Pool: "123456789012", Status: "stopped",
		Config: map[string]string{
			"smbios1": "uuid=5f0c3e9a-8b5d-4b8e-9a51-000000000101",
			"scsi0":   "local:vm-101-disk-0,serial=1123456789abcdef0",
		},
	})
	s.Storages[0].Content = append(s.Storages[0].Content, pvefake.StorageContent{
		VolID: "local:vm-101-disk-0", Content: "images", Size: 8 << 30, VMID: 101,
	})
	b, f := snapshotWriteBackend(t, s, RegionConfig{})
	id, _ := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
	m := backend.Mutation{Scope: inventoryScope(), Key: "same-token", Fingerprint: strings.Repeat("a", 64)}
	beforeCreate := len(f.Requests())
	if _, err := b.CreateSnapshot(t.Context(), m, resource.CreateSnapshotRequest{VolumeID: id}); err != nil {
		t.Fatal(err)
	}
	reads := 0
	for _, request := range f.Requests()[beforeCreate:] {
		if strings.Contains(request, "/storage/local/content") {
			reads++
		}
	}
	if reads != 2 {
		t.Fatalf("storage listings=%d; want one for the guard and one for owner lookup", reads)
	}
	before := len(f.Requests())
	id, _ = resource.Parse[resource.VolumeID]("vol-1123456789abcdef0")
	m.Fingerprint = strings.Repeat("b", 64)
	_, err := b.CreateSnapshot(t.Context(), m, resource.CreateSnapshotRequest{VolumeID: id})
	if resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
		t.Fatalf("token reused on another VM: %v", err)
	}
	for _, request := range f.Requests()[before:] {
		if !strings.HasPrefix(request, "GET ") {
			t.Fatalf("mismatched token wrote PVE: %s", request)
		}
	}
}

func TestSnapshotOperationPublicationWindows(t *testing.T) {
	s := snapshotWriteScenario()
	s.Tokens[0].Secret = "test-secret"
	b, f := snapshotWriteBackend(t, s, RegionConfig{})
	id, _ := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
	m := backend.Mutation{Scope: inventoryScope(), Key: "publication", Fingerprint: strings.Repeat("a", 64)}
	first, err := b.CreateSnapshot(t.Context(), m, resource.CreateSnapshotRequest{VolumeID: id})
	if err != nil {
		t.Fatal(err)
	}
	var finished atomic.Bool
	b.client = startupClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/snapshot"):
			json.NewEncoder(w).Encode(map[string]any{"data": []pveclient.Snapshot{}})
		case strings.HasSuffix(r.URL.Path, "/tasks"):
			rows := []map[string]string{}
			if !finished.Load() {
				rows = append(rows, map[string]string{
					"upid": "UPID:pve1:00000001:00000001:00000001:qmsnapshot:100:vws@pve!inventory:",
				})
			}
			json.NewEncoder(w).Encode(map[string]any{"data": rows})
		default:
			f.ServeHTTP(w, r)
		}
	})
	for _, state := range []resource.OperationState{resource.OperationRunning, resource.OperationFailed} {
		op, err := b.GetOperation(t.Context(), m.Scope, first.Operation.ID)
		if err != nil || op.State != state || state == resource.OperationFailed && op.Error == nil {
			t.Fatalf("publication poll=%+v error=%v; want %v", op, err, state)
		}
		finished.Store(true)
	}
}

func TestSnapshotReplayTaskFinishesDuringDiscovery(t *testing.T) {
	s := snapshotWriteScenario()
	s.Tokens[0].Secret = "test-secret"
	b, f := snapshotWriteBackend(t, s, RegionConfig{})
	if err := f.SetTaskDelay(time.Hour); err != nil {
		t.Fatal(err)
	}
	id, _ := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
	m := backend.Mutation{Scope: inventoryScope(), Key: "discovery", Fingerprint: strings.Repeat("a", 64)}
	req := resource.CreateSnapshotRequest{VolumeID: id}
	first, err := b.CreateSnapshot(t.Context(), m, req)
	if err != nil {
		t.Fatal(err)
	}
	var finished atomic.Bool
	sum := sha256.Sum256([]byte(m.Key))
	b.client = startupClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tasks"):
			finished.Store(true)
			json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
		case strings.HasSuffix(r.URL.Path, "/snapshot") && finished.Load():
			json.NewEncoder(w).Encode(map[string]any{"data": []pveclient.Snapshot{{
				Name:        fmt.Sprintf("vws-%x", sum[:8]),
				Description: "vws:fp=" + m.Fingerprint[:16] + " vws:vol=0123456789abcdef0",
			}}})
		default:
			f.ServeHTTP(w, r)
		}
	})
	retry, err := b.CreateSnapshot(t.Context(), m, req)
	if err != nil || retry.Operation.ID != first.Operation.ID || retry.Items[0].ID != first.Items[0].ID {
		t.Fatalf("finished-task replay=%+v error=%v", retry, err)
	}
}
