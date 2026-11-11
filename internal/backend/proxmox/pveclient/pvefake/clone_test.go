package pvefake_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
)

const writer = "vws@pve!writer"

func writable(t *testing.T) pvefake.Scenario {
	t.Helper()
	s := scenario(t)
	s.Roles = append(s.Roles, pvefake.Role{ID: "Cloner", Privs: []string{
		"VM.Audit", "VM.Clone", "VM.Allocate", "Datastore.AllocateSpace", "SDN.Use",
	}})
	s.Tokens = append(s.Tokens, pvefake.Token{
		ID: writer, Secret: "fake-writer", ACL: []pvefake.ACE{{Path: "/", Role: "Cloner"}},
	})
	return s
}

func call(t *testing.T, f http.Handler, token, method, path, form string, out any) int {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, "/api2/json"+path, strings.NewReader(form))
	key := "fake-writer"
	switch token {
	case auditor:
		key = auditorKey
	case poolA:
		key = poolAKey
	}
	r.Header.Set("Authorization", "PVEAPIToken="+token+"="+key)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if out != nil {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code
}

func clone(t *testing.T, f *pvefake.Fake, id int) string {
	t.Helper()
	var answer struct{ Data string }
	code := call(t, f, writer, "POST", "/nodes/pve1/qemu/9000/clone",
		fmt.Sprintf("newid=%d&pool=vws-a&description=recovery-marker", id), &answer)
	if code != 200 || answer.Data == "" {
		t.Fatalf("clone %d: status=%d answer=%+v", id, code, answer)
	}
	return answer.Data
}

func taskState(t *testing.T, f *pvefake.Fake, token, upid string) pveclient.TaskStatus {
	t.Helper()
	var answer struct{ Data pveclient.TaskStatus }
	if code := call(t, f, token, "GET",
		"/nodes/pve1/tasks/"+url.PathEscape(upid)+"/status", "", &answer); code != 200 {
		t.Fatalf("task status: %d", code)
	}
	return answer.Data
}

func advance(t *testing.T, f *pvefake.Fake, elapsed time.Duration) {
	t.Helper()
	if err := f.Advance(elapsed); err != nil {
		t.Fatal(err)
	}
}

func TestCloneLockAndTaskSurviveClientRestart(t *testing.T) {
	s := writable(t)
	s.VMs[2].Config = map[string]string{
		"scsi0":     "media=disk,file=local-lvm:vm-9000-disk-0",
		"efidisk0":  "efitype=4m,file=local-lvm:vm-9000-disk-1",
		"tpmstate0": "version=v2.0,volume=local-lvm:vm-9000-disk-2",
		"ide2":      "local-lvm:vm-9000-cloudinit,media=cdrom",
		"net0":      "bridge=vmbr0,virtio=BC:24:11:00:00:01,firewall=1",
		"smbios1":   "uuid=9d8c7b6a-5e4f-4a3b-8c2d-1e0f9a8b7c6d,manufacturer=Acme,serial=asset1",
		"vmgenid":   "11111111-2222-4333-8444-555555555555",
		"unused0":   "local-lvm:vm-9000-disk-3",
		"parent":    "base",
		"snaptime":  "1699999999",
	}
	f, srv := start(t, s)
	if err := f.SetTaskDelay(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	upid := clone(t, f, 102)
	// PVE::UPID::encode uses node:pid:pstart:starttime:type:source-vmid:owner.
	if upid != "UPID:pve1:00000001:00000001:6553F100:qmclone:9000:vws@pve!writer:" {
		t.Fatalf("UPID = %q", upid)
	}
	read := func() pveclient.VMConfig {
		c := client(t, srv, auditor, auditorKey)
		cfg, err := c.VMConfig(t.Context(), pveclient.VM{Node: "pve1", VMID: 102})
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	first := read()
	if first.Lock != "clone" || first.Description != "recovery-marker" || first.Template != 0 {
		t.Fatalf("pending config = %+v", first)
	}
	advance(t, f, 3*time.Second-time.Nanosecond)
	if st := taskState(t, f, writer, upid); st.Status != "running" || st.ExitStatus != "" {
		t.Fatalf("before deadline = %+v", st)
	}
	if read().Lock != "clone" {
		t.Fatal("lock cleared before deadline")
	}
	advance(t, f, time.Nanosecond)
	after := read()
	if after.Lock != "" || after.Digest == first.Digest || after.SMBIOS1 != s.VMs[2].Config["smbios1"] {
		t.Fatalf("completed config = %+v", after)
	}
	var copied struct{ Data map[string]any }
	if code := call(t, f, auditor, "GET", "/nodes/pve1/qemu/102/config", "", &copied); code != 200 {
		t.Fatalf("copied config = %d", code)
	}
	for key, value := range s.VMs[2].Config {
		if copied.Data[key] != value {
			t.Fatalf("copied %s = %q, want %q", key, copied.Data[key], value)
		}
	}
	if st := taskState(t, f, writer, upid); st.Status != "stopped" || st.ExitStatus != "OK" {
		t.Fatalf("completed = %+v", st)
	}
	restarted := client(t, srv, auditor, auditorKey)
	if err := restarted.WaitTask(t.Context(), pveclient.Task{Node: "pve1", UPID: upid}, time.Second); err != nil {
		t.Fatal(err)
	}
	advance(t, f, time.Hour)
	if read().Digest != after.Digest {
		t.Fatal("advancing again reapplied a completed task")
	}
}

func TestFailNextIsConsumedByOneAcceptedTaskAndCleansClone(t *testing.T) {
	f, srv := start(t, writable(t))
	f.FailNext("qmclone", "storage full")
	f.FailNext("qmstart", "unrelated")
	if code := call(t, f, writer, "POST", "/nodes/pve1/qemu/9000/clone", "newid=bad", nil); code != 400 {
		t.Fatalf("invalid clone = %d", code)
	}
	failed, succeeded := clone(t, f, 102), clone(t, f, 103)
	advance(t, f, time.Second)
	if st := taskState(t, f, writer, failed); st.ExitStatus != "storage full" {
		t.Fatalf("injected failure = %+v", st)
	}
	err := client(t, srv, auditor, auditorKey).WaitTask(t.Context(),
		pveclient.Task{Node: "pve1", UPID: failed}, time.Second)
	if failure, ok := errors.AsType[*pveclient.TaskError](err); !ok || failure.ExitStatus != "storage full" {
		t.Fatalf("client task failure = %v", err)
	}
	if st := taskState(t, f, writer, succeeded); st.ExitStatus != "OK" {
		t.Fatalf("following task = %+v", st)
	}
	if code := call(t, f, auditor, "GET", "/nodes/pve1/qemu/102/config", "", nil); code != 500 {
		t.Fatalf("failed clone still exists: %d", code)
	}
	retry := clone(t, f, 102)
	advance(t, f, time.Second)
	if st := taskState(t, f, writer, retry); st.ExitStatus != "OK" {
		t.Fatalf("retry = %+v", st)
	}
}

func TestTaskFiltersFollowPVEAPI2Tasks(t *testing.T) {
	s := writable(t)
	other := s.Tokens[len(s.Tokens)-1]
	other.ID = "other@pve!writer"
	s.Tokens = append(s.Tokens, other)
	f, _ := start(t, s)
	first := clone(t, f, 102)
	advance(t, f, time.Second)
	second := clone(t, f, 103)
	if code := call(t, f, other.ID, "POST", "/nodes/pve1/qemu/100/clone", "newid=104", nil); code != 200 {
		t.Fatalf("other user clone = %d", code)
	}
	advance(t, f, time.Second)
	list := func(token, query string) []map[string]any {
		var answer struct{ Data []map[string]any }
		if code := call(t, f, token, "GET", "/nodes/pve1/tasks?"+query, "", &answer); code != 200 {
			t.Fatalf("list = %d", code)
		}
		return answer.Data
	}
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"", 3},
		{"userfilter=VWS%40PVE", 2},
		{"userfilter=missing", 0},
		{"typefilter=qmclone", 3},
		{"typefilter=qmstart", 0},
		{"vmid=9000", 2},
		{"vmid=100", 1},
		{"vmid=999999999", 0},
		{"since=1700000001&until=1700000001", 2},
		{"since=1700000002", 0},
		{"until=1699999999", 0},
		{"source=active", 0},
		{"start=1&limit=1", 1},
		{"limit=0", 0},
	} {
		if rows := list(auditor, tc.query); len(rows) != tc.want {
			t.Errorf("%s: %d rows, want %d", tc.query, len(rows), tc.want)
		}
	}
	rows := list(writer, "")
	if len(rows) != 2 || rows[0]["upid"] != second || rows[1]["upid"] != first ||
		rows[0]["user"] != "vws@pve" || rows[0]["tokenid"] != "writer" || rows[0]["status"] != "OK" {
		t.Fatalf("owner rows = %+v", rows)
	}
	if len(list(poolA, "")) != 0 {
		t.Fatal("unprivileged token listed another token's tasks")
	}
	clone(t, f, 105)
	if len(list(writer, "")) != 2 || len(list(writer, "source=all")) != 3 ||
		len(list(writer, "source=active")) != 1 {
		t.Fatal("running task archive/source filtering")
	}
	for _, query := range []string{
		"since=x", "until=9223372036854775808", "vmid=-1", "vmid=0", "vmid=99", "vmid=1000000000",
		"limit=-1", "source=x",
	} {
		if code := call(t, f, auditor, "GET", "/nodes/pve1/tasks?"+query, "", nil); code != 400 {
			t.Errorf("%s = %d", query, code)
		}
	}
}

func TestNextIDCloneCollision(t *testing.T) {
	f, _ := start(t, writable(t))
	ready, run := make(chan int, 2), make(chan struct{})
	done := make(chan int, 2)
	for range 2 {
		go func() {
			var answer struct{ Data int }
			call(t, f, writer, "GET", "/cluster/nextid", "", &answer)
			ready <- answer.Data
			<-run
			done <- call(t, f, writer, "POST", "/nodes/pve1/qemu/9000/clone",
				"newid="+strconv.Itoa(answer.Data), nil)
		}()
	}
	a, b := <-ready, <-ready
	close(run)
	c, d := <-done, <-done
	if a != 102 || b != a || (c != 200 || d != 500) && (c != 500 || d != 200) {
		t.Fatalf("ids=%d,%d statuses=%d,%d", a, b, c, d)
	}
	if code := call(t, f, writer, "GET", "/cluster/nextid?vmid=102", "", nil); code != 400 {
		t.Fatalf("assert occupied ID = %d", code)
	}
	for _, value := range []string{"99", "1000000000", "x", "-1"} {
		if code := call(t, f, writer, "GET", "/cluster/nextid?vmid="+value, "", nil); code != 400 {
			t.Errorf("nextid %s = %d", value, code)
		}
	}
}

func TestCloneAndTaskACLs(t *testing.T) {
	for _, privilege := range []string{"VM.Clone", "VM.Allocate", "Datastore.AllocateSpace", "SDN.Use"} {
		s := writable(t)
		// Clone the ordinary VM so disk and bridge access are both exercised.
		role := &s.Roles[len(s.Roles)-1]
		role.Privs = slices.DeleteFunc(role.Privs, func(priv string) bool { return priv == privilege })
		f, _ := start(t, s)
		if code := call(t, f, writer, "POST", "/nodes/pve1/qemu/100/clone", "newid=102", nil); code != 403 {
			t.Errorf("without %s = %d", privilege, code)
		}
	}
	f, _ := start(t, writable(t))
	upid := clone(t, f, 102)
	if code := call(t, f, poolA, "GET", "/nodes/pve1/tasks/"+url.PathEscape(upid)+"/status", "", nil); code != 403 {
		t.Fatalf("another token's status = %d", code)
	}
	if code := call(t, f, auditor, "POST", "/nodes/pve1/qemu/9000/clone", "newid=103", nil); code != 403 {
		t.Fatalf("auditor mutation = %d", code)
	}
	if code := call(t, f, "unknown", "GET", "/cluster/nextid", "", nil); code != 401 {
		t.Fatalf("unauthenticated nextid = %d", code)
	}
	if err := f.SetTaskDelay(-time.Second); err == nil {
		t.Fatal("negative delay accepted")
	}
	if err := f.Advance(-time.Second); err == nil {
		t.Fatal("clock moved backwards")
	}
	if err := f.SetTaskDelay(0); err != nil {
		t.Fatal(err)
	}
	immediate := clone(t, f, 103)
	if st := taskState(t, f, writer, immediate); st.Status != "stopped" {
		t.Fatalf("zero delay = %+v", st)
	}
}

func TestCloneRefusesBoundaryInputsWithoutCreatingTasks(t *testing.T) {
	f, _ := start(t, writable(t))
	for _, form := range []string{
		"newid=99", "newid=1000000000", "newid=102&newid=103", "newid=102&skiplock=1",
		"newid=102&full=invalid", "newid=102&description=" + strings.Repeat("a", 64<<10),
	} {
		if code := call(t, f, writer, "POST", "/nodes/pve1/qemu/9000/clone", form, nil); code != 400 {
			t.Errorf("invalid form (length %d) = %d", len(form), code)
		}
	}
	f.SetQuorate(false)
	if code := call(t, f, writer, "POST", "/nodes/pve1/qemu/9000/clone", "newid=102", nil); code != 500 {
		t.Fatalf("no quorum = %d", code)
	}
	f.SetQuorate(true)
	upid := clone(t, f, 102)
	if !strings.Contains(upid, ":00000001:") {
		t.Fatalf("refused calls consumed tasks: %s", upid)
	}
	if code := call(t, f, writer, "POST", "/nodes/pve1/qemu/102/clone", "newid=103", nil); code != 500 {
		t.Fatalf("locked source = %d", code)
	}
}

func TestCloneAcceptsPoolAllocationWithoutSourceAudit(t *testing.T) {
	s := writable(t)
	role := &s.Roles[len(s.Roles)-1]
	role.Privs = []string{"VM.Clone", "VM.Allocate"}
	s.Tokens[len(s.Tokens)-1].ACL = []pvefake.ACE{
		{Path: "/vms/9000", Role: "Cloner"}, {Path: "/pool/vws-a", Role: "Cloner"},
	}
	f, _ := start(t, s)
	upid := clone(t, f, 102)
	advance(t, f, time.Second)
	if st := taskState(t, f, writer, upid); st.ExitStatus != "OK" {
		t.Fatalf("pool allocation = %+v", st)
	}
	if code := call(t, f, poolA, "GET", "/nodes/pve1/qemu/102/config", "", nil); code != 200 {
		t.Fatalf("clone did not join requested pool: %d", code)
	}
}

func TestCloneConfigPrivileges(t *testing.T) {
	const mediaFilename = "file=local:9000/vm-9000-media=cdrom.raw,media=disk"
	for _, tc := range []struct {
		name, path, privilege, key, value string
	}{
		{"physical-cdrom", "/", "Sys.Console", "ide2", "cdrom,media=cdrom"},
		{"volume-cdrom", "/", "Sys.Console", "ide2", "volume=cdrom,media=cdrom"},
		{"file-last", "/", "Sys.Console", "ide2", "media=cdrom,file=cdrom"},
		{"bare-last", "/", "Sys.Console", "ide2", "media=cdrom,cdrom"},
		{"vm-state-storage", "/storage/restricted", "Datastore.AllocateSpace", "vmstatestorage", "restricted"},
		{"disk", "/storage/local-lvm", "Datastore.AllocateSpace", "scsi0", "local-lvm:vm-9000-disk-0"},
		{"file-disk", "/storage/local-lvm", "Datastore.AllocateSpace", "scsi0", "file=local-lvm:vm-9000-disk-0"},
		{"volume-disk", "/storage/local-lvm", "Datastore.AllocateSpace", "scsi0", "volume=local-lvm:vm-9000-disk-0"},
		{"media-first", "/storage/local-lvm", "Datastore.AllocateSpace", "scsi0", "media=disk,file=local-lvm:vm-9000-disk-0"},
		{"filename-media", "/storage/local", "Datastore.AllocateSpace", "scsi0", mediaFilename},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := writable(t)
			s.VMs[2].Config = map[string]string{tc.key: tc.value}
			s.Roles[len(s.Roles)-1].Privs = []string{"VM.Clone", "VM.Allocate"}
			s.Roles = append(s.Roles, pvefake.Role{ID: "Extra", Privs: []string{"VM.Clone", "VM.Allocate", tc.privilege}})
			acl := &s.Tokens[len(s.Tokens)-1].ACL
			*acl = append(*acl, pvefake.ACE{Path: tc.path + "-other", Role: "Extra"})
			f, _ := start(t, s)
			path := "/nodes/pve1/qemu/9000/clone"
			form := "newid=102&full=1&storage=allowed"
			if tc.key == "scsi0" {
				form = "newid=102"
			}
			if code := call(t, f, writer, "POST", path, form, nil); code != 403 {
				t.Fatalf("missing %s on %s = %d", tc.privilege, tc.path, code)
			}
			*acl = append(*acl, pvefake.ACE{Path: tc.path, Role: "Extra"})
			granted, _ := start(t, s)
			if code := call(t, granted, writer, "POST", path, form, nil); code != 200 {
				t.Fatalf("granted %s on %s = %d", tc.privilege, tc.path, code)
			}
		})
	}
}
