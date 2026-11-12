package pvefake

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

type task struct {
	upid, node, kind, id, user string
	pid                        int
	start, end                 int64
	due                        time.Time
	exit                       string
	done                       bool
	apply                      func() string
}

// SetTaskDelay affects tasks submitted after this call.
func (f *Fake) SetTaskDelay(delay time.Duration) error {
	if delay < 0 {
		return fmt.Errorf("pvefake: negative task delay")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delay = delay
	return nil
}

// FailNext queues an exitstatus for the next accepted task of kind.
// Rejected requests do not consume an injected failure.
func (f *Fake) FailNext(kind, exitstatus string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext[kind] = append(f.failNext[kind], exitstatus)
}

func (f *Fake) submit(t *Token, node, kind, id string, apply func() string) string {
	now := f.clock()
	x := &task{
		node: node, kind: kind, id: id, user: t.ID, pid: len(f.tasks) + 1,
		start: now.Unix(), due: now.Add(f.delay), apply: apply,
	}
	x.upid = fmt.Sprintf("UPID:%s:%08X:%08X:%08X:%s:%s:%s:", node, x.pid, 1, x.start, kind, id, t.ID)
	if queue := f.failNext[kind]; len(queue) > 0 {
		x.exit, f.failNext[kind] = queue[0], queue[1:]
	}
	f.tasks = append(f.tasks, x)
	f.settle()
	return x.upid
}

func (f *Fake) settle() {
	now := f.clock()
	var ready []*task
	for _, x := range f.tasks {
		if !x.done && !now.Before(x.due) {
			ready = append(ready, x)
		}
	}
	// An injected clock can cross several deadlines in one step.
	slices.SortStableFunc(ready, func(a, b *task) int { return a.due.Compare(b.due) })
	for _, x := range ready {
		if x.exit == "" {
			x.exit = x.apply()
		}
		x.apply, x.done, x.end = nil, true, x.due.Unix()
		f.archive = append(f.archive, x)
	}
}

func (f *Fake) taskRoutes() {
	f.handle("/nodes/{node}/tasks", f.taskList)
	f.handle("/nodes/{node}/tasks/{upid}/status", f.taskStatus)
	for _, action := range []string{"start", "shutdown", "stop", "reboot"} {
		f.handleMethod(http.MethodPost, "/nodes/{node}/qemu/{vmid}/status/"+action, f.power)
	}
}

func parameter(key, reason string) *failure {
	return &failure{http.StatusBadRequest, "Parameter verification failed. " + key + ": " + reason}
}

func (f *Fake) power(t *Token, r *http.Request) (any, *failure) {
	node, fail := f.node(r)
	if fail != nil {
		return nil, fail
	}
	id := r.PathValue("vmid")
	vmid, err := strconv.Atoi(id)
	if err != nil || vmid < 100 || vmid > 999999999 {
		return nil, parameter("vmid", "value does not match a valid VM ID")
	}
	if fail := f.need(t, "/vms/"+strconv.Itoa(vmid), "VM.PowerMgmt"); fail != nil {
		return nil, fail
	}
	if err := r.ParseForm(); err != nil {
		return nil, parameter("body", "unable to parse parameters")
	}
	// Optional power controls need their own behavioral model before accepting them.
	for key := range r.Form {
		return nil, parameter(key, "property is not defined in the fake's power schema")
	}
	vm := f.vm(vmid)
	if vm == nil || vm.Node != node {
		return nil, &failure{
			http.StatusInternalServerError,
			fmt.Sprintf("Configuration file 'nodes/%s/qemu-server/%d.conf' does not exist", node, vmid),
		}
	}
	action := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	return f.submit(t, node, "qm"+action, strconv.Itoa(vmid), func() string {
		vm := f.vm(vmid)
		if lock := vm.Config["lock"]; lock != "" {
			return "VM is locked (" + lock + ")"
		}
		if vm.Template {
			return "you can't start a vm if it's a template"
		}
		if action == "reboot" && vm.Status != "running" {
			return "VM " + id + " not running"
		}
		vm.Status = "running"
		if action == "shutdown" || action == "stop" {
			vm.Status = "stopped"
		}
		return "OK"
	}), nil
}

func (x *task) row() map[string]any {
	user, token, _ := strings.Cut(x.user, "!")
	row := map[string]any{
		"upid": x.upid, "node": x.node, "pid": x.pid, "pstart": 1,
		"starttime": x.start, "type": x.kind, "id": x.id, "user": user,
	}
	setIf(row, "tokenid", token)
	return row
}

func (f *Fake) taskStatus(t *Token, r *http.Request) (any, *failure) {
	node, fail := f.node(r)
	if fail != nil {
		return nil, fail
	}
	for _, x := range f.tasks {
		if x.upid != r.PathValue("upid") || x.node != node {
			continue
		}
		if x.user != t.ID {
			if fail := f.need(t, "/nodes/"+node, "Sys.Audit"); fail != nil {
				return nil, fail
			}
		}
		row := x.row()
		row["status"] = "running"
		if x.done {
			row["status"], row["exitstatus"] = "stopped", x.exit
		}
		return row, nil
	}
	return nil, parameter("upid", "no such task")
}

func (f *Fake) taskList(t *Token, r *http.Request) (any, *failure) {
	node, fail := f.node(r)
	if fail != nil {
		return nil, fail
	}
	q := r.URL.Query()
	for key, values := range q {
		known := slices.Contains([]string{
			"userfilter", "typefilter", "vmid", "since", "until", "source", "start", "limit",
		}, key)
		if !known || len(values) != 1 {
			return nil, parameter(key, "unknown or repeated parameter")
		}
	}
	num := map[string]int64{"start": 0, "limit": 50}
	for _, key := range []string{"vmid", "since", "until", "start", "limit"} {
		if q.Has(key) {
			n, err := strconv.ParseInt(q.Get(key), 10, 64)
			if err != nil || ((key == "start" || key == "limit") && n < 0) ||
				(key == "vmid" && (n < 100 || n > 999999999)) {
				return nil, parameter(key, "invalid integer")
			}
			num[key] = n
		}
	}
	source := q.Get("source")
	if !q.Has("source") {
		source = "archive"
	}
	if !slices.Contains([]string{"archive", "active", "all"}, source) {
		return nil, parameter("source", "value is not in the enumeration")
	}
	var ordered []*task
	if source != "archive" {
		for _, x := range f.tasks {
			if !x.done {
				ordered = append(ordered, x)
			}
		}
	}
	if source != "active" {
		for i := len(f.archive) - 1; i >= 0; i-- {
			ordered = append(ordered, f.archive[i])
		}
	}
	rows := []map[string]any{}
	count := int64(0)
	for _, x := range ordered {
		user, _, _ := strings.Cut(x.user, "!")
		if x.node != node || (x.user != t.ID && !f.can(t, "/nodes/"+node, "Sys.Audit")) ||
			!strings.Contains(strings.ToLower(user), strings.ToLower(q.Get("userfilter"))) ||
			(q.Has("typefilter") && q.Get("typefilter") != "" && x.kind != q.Get("typefilter")) ||
			(q.Has("vmid") && x.id != strconv.FormatInt(num["vmid"], 10)) ||
			(q.Has("since") && x.start < num["since"]) || (q.Has("until") && x.start > num["until"]) {
			continue
		}
		count++
		if count <= num["start"] || int64(len(rows)) >= num["limit"] {
			continue
		}
		row := x.row()
		row["status"] = "RUNNING"
		if x.done {
			row["status"], row["endtime"] = x.exit, x.end
		}
		rows = append(rows, row)
	}
	return rows, nil
}
