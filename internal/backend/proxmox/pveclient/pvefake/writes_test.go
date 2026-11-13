package pvefake_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
)

func newWriteWorld(t *testing.T, privileges ...string) *taskWorld {
	t.Helper()
	w := &taskWorld{}
	w.now.Store(1700000000)
	s := scenario(t)
	s.Roles = append(s.Roles, pvefake.Role{ID: "Writer", Privs: []string{
		"VM.Allocate", "VM.Clone", "VM.Config.Options", "VM.Config.CPU", "VM.Config.Memory",
		"VM.Config.HWType", "VM.Config.Cloudinit", "Datastore.AllocateSpace", "SDN.Use",
		"VM.Snapshot", "VM.Config.Disk",
	}})
	if len(privileges) > 0 {
		s.Roles[len(s.Roles)-1].Privs = privileges
	}
	s.Storages = []pvefake.Storage{{Node: "pve1", Name: "ceph", Content: []pvefake.StorageContent{
		{VolID: "ceph:vm-100-disk-0", VMID: 100, Size: 8 << 30, Content: "images", Format: "raw"},
	}}, {Node: "pve1", Name: "target"}}
	s.Tokens = append(s.Tokens,
		pvefake.Token{ID: "writer@pve!one", Secret: "k", ACL: []pvefake.ACE{{Path: "/", Role: "Writer"}}},
		pvefake.Token{ID: "scoped@pve!one", Secret: "k", ACL: []pvefake.ACE{
			{Path: "/pool/vws-a", Role: "Writer"}, {Path: "/vms/9000", Role: "Writer"},
		}},
	)
	var err error
	w.f, err = pvefake.NewWithClock(s, func() time.Time { return time.Unix(w.now.Load(), 0) })
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *taskWorld) write(t *testing.T, method, path, body, token string, want int) any {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, "/api2/json"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	key := "k"
	if token == auditor {
		key = auditorKey
	}
	r.Header.Set("Authorization", "PVEAPIToken="+token+"="+key)
	rec := httptest.NewRecorder()
	w.f.ServeHTTP(rec, r)
	if rec.Code != want {
		t.Fatalf("%s %s (%s): %d %s, want %d", method, path, body, rec.Code, rec.Body.String(), want)
	}
	var env struct{ Data any }
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	return env.Data
}

func (w *taskWorld) config(t *testing.T, node string, id int) map[string]any {
	t.Helper()
	var env struct{ Data map[string]any }
	w.call(t, "GET", fmt.Sprintf("/nodes/%s/qemu/%d/config", node, id), auditor, 200, &env)
	return env.Data
}

func TestCloneLockFailureAndClientRestart(t *testing.T) {
	w := newWriteWorld(t)
	w.delay(t, 10)
	w.f.FailNext("qmclone", "storage full")
	path := "/nodes/pve1/qemu/9000/clone"
	w.write(t, "POST", path, "newid=102", auditor, 403)
	failed := w.write(t, "POST", path, "newid=102&full=1&pool=vws-a", "writer@pve!one", 200).(string)
	if st := w.status(t, failed); st.Status != "running" {
		t.Fatal(st)
	}
	if cfg := w.config(t, "pve1", 102); cfg["lock"] != "clone" {
		t.Fatal(cfg)
	}
	w.write(t, "PUT", "/nodes/pve1/qemu/102/config", "description=locked", "writer@pve!one", 500)
	w.now.Add(10)
	if st := w.status(t, failed); st.ExitStatus != "storage full" {
		t.Fatal(st)
	}
	w.call(t, "GET", "/nodes/pve1/qemu/102/config", auditor, 500, nil)
	upid := w.write(t, "POST", path, "newid=102&full=0&pool=vws-a&target=pve2&name=copy&description=hello",
		"scoped@pve!one", 200).(string)
	if cfg := w.config(t, "pve2", 102); cfg["lock"] != "clone" || cfg["description"] != "hello" {
		t.Fatal(cfg)
	}
	w.now.Add(10)
	if st := w.status(t, upid); st.ExitStatus != "OK" {
		t.Fatal(st)
	}
	srv := httptest.NewServer(w.f)
	t.Cleanup(srv.Close)
	for range 2 {
		c := client(t, srv, auditor, auditorKey)
		cfg, err := c.VMConfig(t.Context(), pveclient.VM{Node: "pve2", VMID: 102})
		if err != nil || cfg.Lock != "" || cfg.Template != 0 || cfg.Name != "copy" ||
			cfg.SMBIOS1 == w.config(t, "pve1", 9000)["smbios1"] {
			t.Fatalf("recreated client: %+v %v", cfg, err)
		}
	}
	w.write(t, "POST", path, "newid=102", "writer@pve!one", 500)
}

func TestConfigCASAndAtomicPrivileges(t *testing.T) {
	w := newWriteWorld(t)
	path := "/nodes/pve1/qemu/100/config"
	digest := w.config(t, "pve1", 100)["digest"].(string)
	w.write(t, "PUT", path, "digest="+digest+"&description=one&cores=3&name=web.example&tags=env-prod%3Bteam_a",
		"writer@pve!one", 200)
	for _, method := range []string{"POST", "PUT"} {
		w.write(t, method, path, "digest="+digest+"&description=stale", "writer@pve!one", 500)
	}
	w.delay(t, 10)
	digest = w.config(t, "pve1", 100)["digest"].(string)
	first := w.write(t, "POST", path, "digest="+digest+"&description=two", "writer@pve!one", 200).(string)
	second := w.write(t, "POST", path, "digest="+digest+"&description=lost", "writer@pve!one", 200).(string)
	w.now.Add(10)
	if w.status(t, first).ExitStatus != "OK" ||
		!strings.Contains(w.status(t, second).ExitStatus, "checksum mismatch") {
		t.Fatal("concurrent config writes bypassed CAS")
	}
	cfg := w.config(t, "pve1", 100)
	if cfg["description"] != "two" || cfg["cores"] != float64(3) {
		t.Fatal(cfg)
	}
	w.write(t, "PUT", path, "delete=description,tags", "writer@pve!one", 200)
	if cfg := w.config(t, "pve1", 100); cfg["description"] != nil || cfg["tags"] != nil {
		t.Fatal(cfg)
	}
	w.write(t, "PUT", "/nodes/pve2/qemu/101/config", "description=foreign", "scoped@pve!one", 403)
}

func TestCloneDescriptionAndConfigClientCAS(t *testing.T) {
	w := newWriteWorld(t)
	w.delay(t, 10)
	srv := httptest.NewServer(w.f)
	t.Cleanup(srv.Close)
	c := client(t, srv, "writer@pve!one", "k")
	source := pveclient.VM{Node: "pve1", VMID: 9000}
	upid, err := c.Clone(t.Context(), source, 102, "vws-a", "launch", "key=launch", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg := w.config(t, "pve1", 102); cfg["description"] != "key=launch" || cfg["lock"] != "clone" {
		t.Fatal(cfg)
	}
	w.now.Add(10)
	if w.status(t, upid).ExitStatus != "OK" {
		t.Fatal("clone failed")
	}
	target := pveclient.VM{Node: "pve1", VMID: 102}
	digest := w.config(t, "pve1", 102)["digest"].(string)
	form := url.Values{"cores": {"3"}, "description": {"finalized"}, "digest": {"ignored"}}
	if err := c.WriteConfig(t.Context(), target, digest, form); err != nil {
		t.Fatal(err)
	}
	before := w.config(t, "pve1", 102)
	if before["cores"] != float64(3) || before["description"] != "finalized" || form.Get("digest") != "ignored" {
		t.Fatal(before, form)
	}
	err = c.WriteConfig(t.Context(), target, digest, url.Values{"cores": {"4"}, "description": {"lost"}})
	if !pveclient.DigestConflict(err) {
		t.Fatalf("stale digest = %v", err)
	}
	after := w.config(t, "pve1", 102)
	if after["digest"] != before["digest"] || after["cores"] != float64(3) || after["description"] != "finalized" {
		t.Fatal(after)
	}
	if err := c.WriteConfig(t.Context(), target, "", form); err == nil {
		t.Fatal("empty digest accepted")
	}
	if _, err := c.Clone(t.Context(), source, 0, "", "", "", "", true); err == nil {
		t.Fatal("invalid clone accepted")
	}
}

func TestCloneCopiesDisksAndConfigACLsAreAtomic(t *testing.T) {
	w := newWriteWorld(t)
	w.write(t, "POST", "/nodes/pve1/qemu/100/clone", "newid=102&full=1", "writer@pve!one", 200)
	source, clone := w.config(t, "pve1", 100), w.config(t, "pve1", 102)
	if source["net0"] == clone["net0"] || !strings.Contains(clone["scsi0"].(string), "vm-102-disk-0") {
		t.Fatalf("clone retained source identity: %v", clone)
	}
	var content struct{ Data []pvefake.StorageContent }
	w.call(t, "GET", "/nodes/pve1/storage/ceph/content", auditor, 200, &content)
	if len(content.Data) != 2 || content.Data[1].VMID != 102 || content.Data[1].Size != 8<<30 {
		t.Fatal(content)
	}
	cpu := newWriteWorld(t, "VM.Config.CPU")
	cpu.write(t, "PUT", "/nodes/pve1/qemu/100/config", "cores=3&description=forbidden", "writer@pve!one", 403)
	if cfg := cpu.config(t, "pve1", 100); cfg["cores"] != float64(2) || cfg["description"] != nil {
		t.Fatal(cfg)
	}
	for _, privileges := range [][]string{{"VM.Clone"}, {"VM.Allocate"}, {"VM.Clone", "VM.Allocate"}} {
		limited := newWriteWorld(t, privileges...)
		limited.write(t, "POST", "/nodes/pve1/qemu/100/clone", "newid=102&full=1", "writer@pve!one", 403)
	}
}

func TestNextIDConcurrentCloneCollision(t *testing.T) {
	w := newWriteWorld(t)
	if err := w.f.SetNextIDs(102, 102); err != nil {
		t.Fatal(err)
	}
	ready, release := make(chan int, 2), make(chan struct{})
	results := make(chan int, 2)
	for range 2 {
		go func() {
			var next struct{ Data int }
			w.call(t, "GET", "/cluster/nextid", auditor, 200, &next)
			ready <- next.Data
			<-release
			r := httptest.NewRequestWithContext(t.Context(), "POST",
				fmt.Sprintf("/api2/json/nodes/pve1/qemu/9000/clone?newid=%d", next.Data), nil)
			r.Header.Set("Authorization", "PVEAPIToken=writer@pve!one=k")
			rec := httptest.NewRecorder()
			w.f.ServeHTTP(rec, r)
			results <- rec.Code
		}()
	}
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	defer close(release)
	for range 2 {
		select {
		case id := <-ready:
			if id != 102 {
				t.Fatalf("forced ID = %d", id)
			}
		case <-timeout.C:
			t.Fatal("nextid barrier timed out")
		}
	}
	release <- struct{}{}
	release <- struct{}{}
	sum := 0
	for range 2 {
		select {
		case code := <-results:
			sum += code
		case <-timeout.C:
			t.Fatal("clone completion timed out")
		}
	}
	if sum != 700 {
		t.Fatalf("clone status sum = %d, want 200 + 500", sum)
	}
	w.call(t, "GET", "/cluster/nextid?vmid=102", auditor, 500, nil)
	w.call(t, "GET", "/cluster/nextid?vmid=103", auditor, 200, nil)
	if err := w.f.SetNextIDs(99); err == nil {
		t.Fatal("invalid hook ID accepted")
	}
}

func TestCreateDeleteProtectionAndFailures(t *testing.T) {
	w := newWriteWorld(t)
	w.f.FailNext("qmcreate", "no space")
	id := w.write(t, "POST", "/nodes/pve1/qemu", "vmid=102&start=0", "writer@pve!one", 200).(string)
	if w.status(t, id).ExitStatus != "no space" {
		t.Fatal("create failure lost")
	}
	w.write(t, "POST", "/nodes/pve1/qemu", "vmid=102&pool=vws-a&start=0&protection=1&cores=2&memory=512",
		"scoped@pve!one", 200)
	w.write(t, "DELETE", "/nodes/pve1/qemu/102", "purge=1&destroy-unreferenced-disks=1", "writer@pve!one", 500)
	w.write(t, "PUT", "/nodes/pve1/qemu/102/config", "protection=0", "writer@pve!one", 200)
	w.f.FailNext("qmdestroy", "busy")
	id = w.write(t, "DELETE", "/nodes/pve1/qemu/102", "", "writer@pve!one", 200).(string)
	if w.status(t, id).ExitStatus != "busy" || w.config(t, "pve1", 102)["protection"] != float64(0) {
		t.Fatal("failed deletion changed VM")
	}
	id = w.write(t, "DELETE", "/nodes/pve1/qemu/102", "purge=1&destroy-unreferenced-disks=1",
		"writer@pve!one", 200).(string)
	if w.status(t, id).ExitStatus != "OK" {
		t.Fatal("delete failed")
	}
	w.call(t, "GET", "/nodes/pve1/qemu/102/config", auditor, 500, nil)
	w.write(t, "DELETE", "/nodes/pve1/qemu/102", "", "writer@pve!one", 500)
}

func TestMutationACLAndBoundaryRefusals(t *testing.T) {
	w := newWriteWorld(t)
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/nodes/pve1/qemu/9000/clone", "newid=102"},
		{"POST", "/nodes/pve1/qemu", "vmid=102&start=0"},
		{"PUT", "/nodes/pve1/qemu/100/config", "description=x"},
		{"POST", "/nodes/pve1/qemu/100/config", "cores=3"},
		{"DELETE", "/nodes/pve1/qemu/100", "purge=1"},
	} {
		w.write(t, tc.method, tc.path, tc.body, auditor, 403)
		w.write(t, tc.method, tc.path, tc.body, "unknown@pve!one", 401)
		w.f.SetQuorate(false)
		w.write(t, tc.method, tc.path, tc.body, "writer@pve!one", 500)
		w.f.SetQuorate(true)
	}
	for _, tc := range []struct{ path, body string }{
		{"/nodes/pve1/qemu", "vmid=99"},
		{"/nodes/pve1/qemu", "vmid=102&start=1"},
		{"/nodes/pve1/qemu", "vmid=102&cores=-1"},
		{"/nodes/pve1/qemu", "vmid=102&unknown=1"},
		{"/nodes/pve1/qemu/9000/clone", "newid=102&full=2"},
		{"/nodes/pve1/qemu/9000/clone", "newid=102&newid=103"},
		{"/nodes/pve1/qemu/9000/clone", "newid=102&target=unknown"},
		{"/nodes/pve1/qemu/100/config", "delete=lock"},
		{"/nodes/pve1/qemu/100/config", "cores=wrong"},
		{"/nodes/pve1/qemu", "vmid=102&name=bad_name"},
		{"/nodes/pve1/qemu/9000/clone", "newid=102&name=bad..name"},
		{"/nodes/pve1/qemu/100/config", "cores=3&tags=bad%24tag"},
	} {
		w.write(t, "POST", tc.path, tc.body, "writer@pve!one", 400)
	}
	w.write(t, "POST", "/nodes/pve1/qemu", "vmid=102&pool=vws-b", "scoped@pve!one", 403)
	w.write(t, "POST", "/nodes/pve1/qemu/100/clone", "newid=102", "scoped@pve!one", 403)
	w.call(t, "GET", "/cluster/nextid?vmid="+url.QueryEscape("bad"), auditor, 400, nil)
	w.call(t, "GET", "/cluster/nextid?unknown=1", auditor, 400, nil)
	if len(w.f.PoolWriteViolations()) != 0 {
		t.Fatal(w.f.PoolWriteViolations())
	}
}
