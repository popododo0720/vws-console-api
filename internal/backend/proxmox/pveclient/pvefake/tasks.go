package pvefake

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
)

type task struct {
	upid, node, owner string
	pid               int
	status            pveclient.TaskStatus
	due               time.Time
	end               int64
	exit              string
	target            int
	pool              string
}

// SetTaskDelay sets the duration of subsequent tasks on the fake clock.
func (f *Fake) SetTaskDelay(delay time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if delay < 0 {
		return fmt.Errorf("pvefake: negative task delay")
	}
	f.delay = delay
	return nil
}

// FailNext makes the next accepted task of kind end with exitstatus.
func (f *Fake) FailNext(kind, exitstatus string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext[kind] = exitstatus
}

// Advance moves the clock from its initial Unix epoch 1700000000 and finishes
// due tasks. Neither HTTP calls nor wall-clock time advance it.
func (f *Fake) Advance(elapsed time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if elapsed < 0 {
		return fmt.Errorf("pvefake: cannot move clock backwards")
	}
	f.now = f.now.Add(elapsed)
	f.finishTasks()
	return nil
}

func (f *Fake) finishTasks() {
	for _, t := range f.tasks {
		if t.end != 0 || t.due.After(f.now) {
			continue
		}
		t.end = t.due.Unix()
		t.status.Status, t.status.ExitStatus = "stopped", t.exit
		if t.exit == "OK" {
			vm := f.vm(t.target)
			delete(vm.Config, "lock")
			vm.Pool = t.pool
		} else {
			for i, vm := range f.s.VMs {
				if vm.VMID == t.target {
					f.s.VMs = append(f.s.VMs[:i], f.s.VMs[i+1:]...)
					break
				}
			}
		}
	}
}

func (f *Fake) cloneTask(t *Token, node string, source, target int, pool string) string {
	pid := len(f.tasks) + 1
	start := f.now.Unix()
	upid := fmt.Sprintf("UPID:%s:%08X:%08X:%08X:qmclone:%d:%s:", node, pid, pid, start, source, t.ID)
	exit := "OK"
	if injected, ok := f.failNext["qmclone"]; ok {
		exit = injected
		delete(f.failNext, "qmclone")
	}
	f.tasks = append(f.tasks, &task{
		upid: upid, node: node, owner: t.ID, pid: pid, due: f.now.Add(f.delay), exit: exit,
		target: target, pool: pool,
		status: pveclient.TaskStatus{Status: "running", Type: "qmclone", ID: strconv.Itoa(source), StartTime: start},
	})
	f.finishTasks()
	return upid
}

func (t *task) row(list bool) map[string]any {
	user, token, _ := strings.Cut(t.owner, "!")
	row := map[string]any{
		"upid": t.upid, "node": t.node, "pid": t.pid, "pstart": t.pid,
		"starttime": t.status.StartTime, "type": t.status.Type, "id": t.status.ID,
		"user": user, "tokenid": token, "status": t.status.Status,
	}
	if t.end != 0 {
		if list {
			row["status"], row["endtime"] = t.exit, t.end
		} else {
			row["exitstatus"] = t.exit
		}
	} else if list {
		row["status"] = "RUNNING"
	}
	return row
}

func (f *Fake) taskStatus(tok *Token, r *http.Request) (any, *failure) {
	node, fail := f.node(r)
	if fail != nil {
		return nil, fail
	}
	for _, t := range f.tasks {
		if t.upid != r.PathValue("upid") || t.node != node {
			continue
		}
		if t.owner != tok.ID {
			if fail := f.need(tok, "/nodes/"+node, "Sys.Audit"); fail != nil {
				return nil, fail
			}
		}
		return t.row(false), nil
	}
	return nil, &failure{http.StatusBadRequest, "Parameter verification failed. upid: no such task"}
}

func (f *Fake) taskList(tok *Token, r *http.Request) (any, *failure) {
	node, fail := f.node(r)
	if fail != nil {
		return nil, fail
	}
	q := r.URL.Query()
	source := q.Get("source")
	if source != "" && source != "archive" && source != "active" && source != "all" {
		return nil, &failure{http.StatusBadRequest, "Parameter verification failed. source: invalid value"}
	}
	filterVMID := ""
	if q.Has("vmid") {
		id, fail := vmID(q.Get("vmid"))
		if fail != nil {
			return nil, fail
		}
		filterVMID = strconv.Itoa(id)
	}
	numbers := map[string]int64{"since": -1 << 63, "until": 1<<63 - 1, "start": 0, "limit": 50}
	for k := range numbers {
		if value := q.Get(k); value != "" {
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || ((k == "start" || k == "limit") && n < 0) {
				return nil, &failure{http.StatusBadRequest, "Parameter verification failed. " + k + ": invalid integer"}
			}
			numbers[k] = n
		}
	}
	rows := []map[string]any{}
	for _, active := range []bool{true, false} {
		for i := len(f.tasks) - 1; i >= 0; i-- {
			t := f.tasks[i]
			user, _, _ := strings.Cut(t.owner, "!")
			if (t.end == 0) != active || (t.owner != tok.ID && !f.can(tok, "/nodes/"+node, "Sys.Audit")) ||
				((source == "" || source == "archive") && t.end == 0) || (source == "active" && t.end != 0) ||
				(q.Get("typefilter") != "" && q.Get("typefilter") != t.status.Type) ||
				!strings.Contains(strings.ToLower(user), strings.ToLower(q.Get("userfilter"))) ||
				t.node != node || (filterVMID != "" && filterVMID != t.status.ID) ||
				t.status.StartTime < numbers["since"] || t.status.StartTime > numbers["until"] {
				continue
			}
			rows = append(rows, t.row(true))
		}
	}
	start := min(numbers["start"], int64(len(rows)))
	return rows[start : start+min(numbers["limit"], int64(len(rows))-start)], nil
}
