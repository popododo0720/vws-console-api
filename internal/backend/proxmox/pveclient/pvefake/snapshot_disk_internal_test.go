package pvefake

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestDeferredTasksRereadState removes the snapshot or disk a queued task
// names before the task runs; the task must fail instead of panicking.
func TestDeferredTasksRereadState(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body, exit string
		remove                         func(f *Fake)
	}{
		{
			"delete", http.MethodDelete, "/snapshot/one", "", "snapshot 'one' does not exist",
			func(f *Fake) { f.vm(100).Snapshots = nil },
		},
		{
			"create", http.MethodPost, "/snapshot", "snapname=two", "snapshot name 'two' already used",
			func(f *Fake) { f.vm(100).Snapshots = append(f.vm(100).Snapshots, Snapshot{Name: "two"}) },
		},
		{
			"resize", http.MethodPut, "/resize", "disk=scsi0&size=10G", "disk 'scsi0' does not exist",
			func(f *Fake) { f.s.Storages[0].Content = nil },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Load("testdata/default.yaml")
			if err != nil {
				t.Fatal(err)
			}
			s.Roles = append(s.Roles, Role{ID: "Writer", Privs: []string{"VM.Snapshot", "VM.Config.Disk"}})
			s.Tokens = append(s.Tokens, Token{ID: "writer@pve!one", Secret: "k", ACL: []ACE{{Path: "/", Role: "Writer"}}})
			s.Storages = []Storage{{Node: "pve1", Name: "ceph", Content: []StorageContent{
				{VolID: "ceph:vm-100-disk-0", VMID: 100, Size: 8 << 30, Content: "images", Format: "raw"},
			}}}
			var now atomic.Int64
			now.Store(1700000000)
			f, err := NewWithClock(s, func() time.Time { return time.Unix(now.Load(), 0) })
			if err != nil {
				t.Fatal(err)
			}
			call := func(method, path, body string) *httptest.ResponseRecorder {
				r := httptest.NewRequestWithContext(t.Context(), method, "/api2/json/nodes/pve1/qemu/100"+path,
					strings.NewReader(body))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("Authorization", "PVEAPIToken=writer@pve!one=k")
				rec := httptest.NewRecorder()
				f.ServeHTTP(rec, r)
				if rec.Code != http.StatusOK {
					t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body.String())
				}
				return rec
			}
			call(http.MethodPost, "/snapshot", "snapname=one")
			if err := f.SetTaskDelay(5 * time.Second); err != nil {
				t.Fatal(err)
			}
			call(tc.method, tc.path, tc.body)
			f.mu.Lock()
			tc.remove(f)
			f.mu.Unlock()
			now.Add(5)
			f.mu.Lock()
			f.settle()
			last := f.tasks[len(f.tasks)-1]
			done, exit, lock := last.done, last.exit, f.vm(100).Config["lock"]
			f.mu.Unlock()
			if !done || exit != tc.exit || lock != "" {
				t.Fatalf("task done=%v exit=%q lock=%q, want exit %q and no lock", done, exit, lock, tc.exit)
			}
		})
	}
}
