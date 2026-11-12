package pvefake_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
)

type taskWorld struct {
	f   *pvefake.Fake
	now atomic.Int64
}

func newTaskWorld(t *testing.T) *taskWorld {
	t.Helper()
	w := &taskWorld{}
	w.now.Store(1700000000)
	s := scenario(t)
	s.Roles = append(s.Roles, pvefake.Role{ID: "Power", Privs: []string{"VM.PowerMgmt"}})
	for _, id := range []string{"alice@pve!one", "alice@pve!two", "bob@pve!one"} {
		s.Tokens = append(s.Tokens, pvefake.Token{
			ID: id, Secret: "k",
			ACL: []pvefake.ACE{{Path: "/", Role: "Power"}},
		})
	}
	var err error
	w.f, err = pvefake.NewWithClock(s, func() time.Time { return time.Unix(w.now.Load(), 0) })
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *taskWorld) call(t *testing.T, method, path, token string, want int, out any) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, "/api2/json"+path, nil)
	key := "k"
	if token == auditor {
		key = auditorKey
	}
	req.Header.Set("Authorization", "PVEAPIToken="+token+"="+key)
	rec := httptest.NewRecorder()
	w.f.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("%s %s: %d %s, want %d", method, path, rec.Code, rec.Body.String(), want)
	}
	if out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatal(err)
		}
	}
}

func (w *taskWorld) delay(t *testing.T, seconds int) {
	t.Helper()
	if err := w.f.SetTaskDelay(time.Duration(seconds) * time.Second); err != nil {
		t.Fatal(err)
	}
}

func (w *taskWorld) power(t *testing.T, id int, action, token string) string {
	t.Helper()
	var env struct{ Data string }
	w.call(t, http.MethodPost, fmt.Sprintf("/nodes/pve1/qemu/%d/status/%s", id, action), token, 200, &env)
	return env.Data
}

func (w *taskWorld) status(t *testing.T, upid string) pveclient.TaskStatus {
	t.Helper()
	var env struct{ Data pveclient.TaskStatus }
	w.call(t, http.MethodGet, "/nodes/pve1/tasks/"+url.PathEscape(upid)+"/status", auditor, 200, &env)
	return env.Data
}

func (w *taskWorld) list(t *testing.T, query, token string) []map[string]any {
	t.Helper()
	var env struct{ Data []map[string]any }
	w.call(t, http.MethodGet, "/nodes/pve1/tasks?"+query, token, 200, &env)
	return env.Data
}

func TestTaskDelayFailureAndStatus(t *testing.T) {
	w := newTaskWorld(t)
	w.delay(t, 10)
	w.f.FailNext("qmstop", "storage full")
	w.call(t, http.MethodPost, "/nodes/pve1/qemu/100/status/stop", auditor, 403, nil)
	start := w.power(t, 100, "start", "alice@pve!one")
	failed := w.power(t, 100, "stop", "alice@pve!one")
	retry := w.power(t, 100, "stop", "alice@pve!one")
	if !regexp.MustCompile(`^UPID:pve1:[0-9A-F]{8}:[0-9A-F]{8}:6553F100:qmstop:100:alice@pve!one:$`).MatchString(failed) {
		t.Fatalf("UPID = %q", failed)
	}
	for _, id := range []string{start, failed, retry} {
		if st := w.status(t, id); st.Status != "running" || st.ExitStatus != "" {
			t.Fatalf("before deadline: %+v", st)
		}
	}
	w.now.Add(9)
	if st := w.status(t, failed); st.Status != "running" {
		t.Fatalf("early completion: %+v", st)
	}
	w.now.Add(1)
	for id, exit := range map[string]string{start: "OK", failed: "storage full", retry: "OK"} {
		st := w.status(t, id)
		if st.Status != "stopped" || st.ExitStatus != exit || st.Type == "" || st.StartTime != 1700000000 {
			t.Fatalf("completed: %+v, want %q", st, exit)
		}
		if again := w.status(t, id); again != st {
			t.Fatalf("status changed: %+v -> %+v", st, again)
		}
	}
	var inventory struct{ Data []pveclient.ClusterResource }
	w.call(t, http.MethodGet, "/cluster/resources?type=vm", auditor, 200, &inventory)
	if inventory.Data[0].Status != "stopped" {
		t.Fatalf("completed stop did not change inventory: %+v", inventory.Data)
	}
	if err := w.f.SetTaskDelay(-time.Second); err == nil {
		t.Fatal("negative delay accepted")
	}
	if _, err := pvefake.NewWithClock(scenario(t), nil); err == nil {
		t.Fatal("nil clock accepted")
	}
}

func TestTaskClientBoundaryAndFailureLeavesVMUnchanged(t *testing.T) {
	w := newTaskWorld(t)
	srv := httptest.NewServer(w.f)
	t.Cleanup(srv.Close)
	c := client(t, srv, auditor, auditorKey)
	w.f.FailNext("qmstop", "storage full")
	id := w.power(t, 100, "stop", "alice@pve!one")
	err := c.WaitTask(t.Context(), pveclient.Task{Node: "pve1", UPID: id}, time.Second)
	te, ok := errors.AsType[*pveclient.TaskError](err)
	if !ok || te.ExitStatus != "storage full" {
		t.Fatalf("WaitTask = %v", err)
	}
	rows, err := c.ClusterResources(t.Context(), pveclient.ResourceVM)
	if err != nil || rows[0].Status != "running" {
		t.Fatalf("failed stop changed VM: %+v, %v", rows, err)
	}
	id = w.power(t, 100, "stop", "alice@pve!one")
	if err := c.WaitTask(t.Context(), pveclient.Task{Node: "pve1", UPID: id}, time.Second); err != nil {
		t.Fatal(err)
	}
	rows, err = c.ClusterResources(t.Context(), pveclient.ResourceVM)
	if err != nil || rows[0].Status != "stopped" {
		t.Fatalf("retry did not stop VM: %+v, %v", rows, err)
	}
	w2 := newTaskWorld(t)
	if rows := w2.list(t, "", auditor); len(rows) != 0 {
		t.Fatalf("fresh scenario retained tasks: %v", rows)
	}
}

func TestTaskFiltersAndOrdering(t *testing.T) {
	w := newTaskWorld(t)
	w.delay(t, 30)
	first := w.power(t, 100, "start", "alice@pve!one")
	w.now.Add(1)
	w.delay(t, 5)
	second := w.power(t, 100, "shutdown", "bob@pve!one")
	w.now.Add(1)
	third := w.power(t, 100, "stop", "alice@pve!two")
	active := w.list(t, "source=active", auditor)
	if len(active) != 3 || active[0]["upid"] != first || active[1]["upid"] != second || active[2]["upid"] != third {
		t.Fatalf("active order = %v", active)
	}
	if rows := w.list(t, "", auditor); len(rows) != 0 {
		t.Fatalf("default includes active tasks: %v", rows)
	}
	w.now.Add(40)
	all := w.list(t, "", auditor)
	if len(all) != 3 || all[0]["upid"] != first || all[1]["upid"] != third || all[2]["upid"] != second {
		t.Fatalf("archive completion order = %v", all)
	}
	for _, tc := range []struct {
		query string
		want  []string
	}{
		{"userfilter=ALICE", []string{first, third}},
		{"userfilter=one", nil}, // userfilter matches the user, not the token name.
		{"typefilter=qmshutdown", []string{second}},
		{"vmid=101", nil},
		{"vmid=100&since=1700000001&until=1700000002", []string{third, second}},
		{"since=1700000002&until=1700000002", []string{third}},
		{"until=1699999999", nil},
		{"start=1&limit=1", []string{third}},
		{"limit=0", nil},
		{"source=active", nil},
		{"source=all", []string{first, third, second}},
	} {
		var got []string
		for _, row := range w.list(t, tc.query, auditor) {
			got = append(got, row["upid"].(string))
			if row["user"] == "alice@pve" && row["tokenid"] == "" {
				t.Fatalf("missing tokenid: %v", row)
			}
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s = %v, want %v", tc.query, got, tc.want)
		}
	}
	if rows := w.list(t, "", "alice@pve!one"); len(rows) != 1 || rows[0]["upid"] != first {
		t.Fatalf("token saw another token's task: %v", rows)
	}
	w.call(t, http.MethodGet, "/nodes/pve1/tasks/"+second+"/status", "alice@pve!one", 403, nil)
	w.call(t, http.MethodGet, "/nodes/pve1/tasks/"+first+"/status", "alice@pve!one", 200, nil)
	w.call(t, http.MethodGet, "/nodes/pve2/tasks/"+second+"/status", auditor, 400, nil)
	for _, query := range []string{
		"vmid=99", "vmid=1000000000", "vmid=x", "since=x", "until=x", "start=-1",
		"limit=-1", "source=wrong", "source=", "vmid=100&vmid=101", "ignored=1",
	} {
		w.call(t, http.MethodGet, "/nodes/pve1/tasks?"+query, auditor, 400, nil)
	}
	w.call(t, http.MethodGet, "/nodes/pve1/tasks/bad/status", auditor, 400, nil)
}

func TestPowerPathsRequirePowerPrivilege(t *testing.T) {
	for _, action := range []string{"start", "shutdown", "stop", "reboot"} {
		t.Run(action, func(t *testing.T) {
			w := newTaskWorld(t)
			path := "/nodes/pve1/qemu/100/status/" + action
			w.call(t, http.MethodPost, path, auditor, 403, nil)
			w.call(t, http.MethodPost, path, "unknown@pve!token", 401, nil)
			if action == "start" {
				w.power(t, 100, "stop", "alice@pve!one")
			}
			id := w.power(t, 100, action, "alice@pve!one")
			if st := w.status(t, id); st.ExitStatus != "OK" {
				t.Fatalf("power task: %+v", st)
			}
			var inventory struct{ Data []pveclient.ClusterResource }
			w.call(t, http.MethodGet, "/cluster/resources?type=vm", auditor, 200, &inventory)
			want := "running"
			if action == "stop" || action == "shutdown" {
				want = "stopped"
			}
			if inventory.Data[0].Status != want {
				t.Fatalf("%s leaves VM %s, want %s", action, inventory.Data[0].Status, want)
			}
		})
	}
	w := newTaskWorld(t)
	for path, code := range map[string]int{
		"/nodes/pve1/qemu/99/status/start":             400,
		"/nodes/pve1/qemu/999/status/start":            500,
		"/nodes/pve1/qemu/101/status/start":            500,
		"/nodes/pve1/qemu/100/status/start?skiplock=1": 400,
	} {
		w.call(t, http.MethodPost, path, "alice@pve!one", code, nil)
	}
}

func TestConcurrentTasksHaveDistinctUPIDs(t *testing.T) {
	w := newTaskWorld(t)
	w.delay(t, 10)
	gate := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan string, 8)
	for range 8 {
		wg.Go(func() {
			<-gate
			results <- w.power(t, 100, "start", "alice@pve!one")
		})
	}
	close(gate)
	wg.Wait()
	close(results)
	seen := map[string]bool{}
	for id := range results {
		if seen[id] || !strings.HasPrefix(id, "UPID:pve1:") {
			t.Fatalf("duplicate or invalid UPID %q", id)
		}
		seen[id] = true
	}
	if rows := w.list(t, "source=active", auditor); len(rows) != 8 {
		t.Fatalf("concurrent tasks = %v", rows)
	}
	w.now.Add(10)
	if rows := w.list(t, "", auditor); len(rows) != 8 {
		t.Fatalf("completed concurrent tasks = %v", rows)
	}
}
