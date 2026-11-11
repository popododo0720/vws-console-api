package pvefake

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fake answers the PVE API from one Scenario.
type Fake struct {
	mu       sync.RWMutex
	s        Scenario
	roles    map[string][]string
	quorate  bool
	online   map[string]bool
	mux      *http.ServeMux
	methods  []string
	requests []string
	now      time.Time
	delay    time.Duration
	tasks    []*task
	failNext map[string]string
}

// failure is a PVE error answer: the status and PVE's message.
type failure struct {
	status int
	msg    string
}

// New checks s and returns a Fake with every node online and with quorum.
// The Fake keeps its own copy: editing s afterwards does not change it.
// Tasks last one fake-clock second by default; Advance completes them.
func New(s Scenario) (*Fake, error) {
	if err := s.check(); err != nil {
		return nil, fmt.Errorf("pvefake: %w", err)
	}
	s = s.clone()
	f := &Fake{s: s, roles: map[string][]string{}, quorate: true, online: map[string]bool{}, mux: http.NewServeMux()}
	f.now, f.delay, f.failNext = time.Unix(1700000000, 0), time.Second, map[string]string{}
	for _, r := range s.Roles {
		f.roles[r.ID] = r.Privs
	}
	for _, n := range s.Nodes {
		f.online[n.Name] = true
	}
	f.routes()
	return f, nil
}

// SetQuorate sets the quorate field of the type=cluster row.
func (f *Fake) SetQuorate(quorate bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.quorate = quorate
}

// SetNodeOnline marks a node online or offline. Calls proxied to an offline
// node answer 595, as pveproxy does when it cannot reach the node.
func (f *Fake) SetNodeOnline(node string, online bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.online[node]; !ok {
		return fmt.Errorf("pvefake: unknown node %q", node)
	}
	f.online[node] = online
	return nil
}

// ServeHTTP answers one API call.
func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.methods = append(f.methods, r.Method)
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	f.mux.ServeHTTP(w, r)
}

// Requests returns method and path for every request, including rejected ones.
func (f *Fake) Requests() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return append([]string(nil), f.requests...)
}

// MoveVM changes pool membership between inventory calls.
func (f *Fake) MoveVM(vmid int, pool string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	vm := f.vm(vmid)
	if vm == nil {
		return fmt.Errorf("pvefake: unknown VM %d", vmid)
	}
	vm.Pool = pool
	return nil
}

// RequestMethods returns every request method, including rejected requests.
func (f *Fake) RequestMethods() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return append([]string(nil), f.methods...)
}

func (f *Fake) handle(pattern string, h func(*Token, *http.Request) (any, *failure)) {
	f.mux.HandleFunc("GET /api2/json"+pattern, func(w http.ResponseWriter, r *http.Request) {
		f.mu.RLock()
		defer f.mu.RUnlock()
		t := f.token(r.Header.Get("Authorization"))
		if t == nil {
			reply(w, nil, &failure{http.StatusUnauthorized, "authentication failure"})
			return
		}
		data, fail := h(t, r)
		reply(w, data, fail)
	})
}

func reply(w http.ResponseWriter, data any, fail *failure) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	body := map[string]any{"data": data}
	status := http.StatusOK
	if fail != nil {
		status, body["message"] = fail.status, fail.msg+"\n"
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body) //nolint:errcheck // the client is gone; a fake has no one to tell
}

// token returns the token the Authorization header names with its secret.
func (f *Fake) token(auth string) *Token {
	v, ok := strings.CutPrefix(auth, "PVEAPIToken=")
	if !ok {
		return nil
	}
	id, secret, _ := strings.Cut(v, "=")
	for i := range f.s.Tokens {
		t := &f.s.Tokens[i]
		if t.ID == id && subtle.ConstantTimeCompare([]byte(t.Secret), []byte(secret)) == 1 {
			return t
		}
	}
	return nil
}

// need is a 403 unless t holds one of privs on p.
func (f *Fake) need(t *Token, p string, privs ...string) *failure {
	held := f.privs(t, p)
	for _, x := range privs {
		if _, ok := held[x]; ok {
			return nil
		}
	}
	return &failure{http.StatusForbidden, fmt.Sprintf("Permission check failed (%s, %s)", p, strings.Join(privs, "|"))}
}

func (f *Fake) can(t *Token, p string, privs ...string) bool { return f.need(t, p, privs...) == nil }

// privs maps each privilege t holds on p to 1 when it propagates, as PVE's
// RPCEnvironment::compile_acl_path does. A VM in a pool adds the roles held on
// /pool/<pool> itself, propagating or not, at 0, and NoAccess anywhere in the
// result removes every privilege.
func (f *Fake) privs(t *Token, p string) map[string]int {
	roles := f.walk(t, p)
	if id, ok := strings.CutPrefix(p, "/vms/"); ok {
		if vmid, err := strconv.Atoi(id); err == nil && id == strconv.Itoa(vmid) {
			if vm := f.vm(vmid); vm != nil && vm.Pool != "" {
				for r := range f.walk(t, "/pool/"+vm.Pool) {
					if _, held := roles[r]; !held {
						roles[r] = 0
					}
				}
			}
		}
	}
	held := map[string]int{}
	if _, ok := roles["NoAccess"]; ok {
		return held
	}
	for r, v := range roles {
		for _, priv := range f.roles[r] {
			held[priv] = max(held[priv], v)
		}
	}
	return held
}

// levels is p and every path above it, "/" first.
func levels(p string) []string {
	out := []string{"/"}
	for i := 1; i < len(p); i++ {
		if p[i] == '/' {
			out = append(out, p[:i])
		}
	}
	if p != "/" {
		out = append(out, p)
	}
	return out
}

func (f *Fake) walk(t *Token, p string) map[string]int {
	levels := levels(p)
	// From "/" down, a level with entries for the token replaces the roles it
	// inherited; above p itself only propagating entries count.
	roles := map[string]int{}
	for i, level := range levels {
		var here map[string]int
		for _, a := range t.ACL {
			if a.Path != level || (i < len(levels)-1 && !a.propagates()) {
				continue
			}
			if here == nil {
				here = map[string]int{}
			}
			here[a.Role] = max(here[a.Role], b2i(a.propagates()))
		}
		if here != nil {
			roles = here
		}
	}
	return roles
}

// node is the node of the path, or PVE's answer for an unknown or offline one.
func (f *Fake) node(r *http.Request) (string, *failure) {
	name := r.PathValue("node")
	online, ok := f.online[name]
	switch {
	case !ok:
		return "", &failure{http.StatusInternalServerError, fmt.Sprintf("hostname lookup '%s' failed", name)}
	case !online:
		return "", &failure{595, "No route to host"}
	}
	return name, nil
}

func (f *Fake) vm(vmid int) *VM {
	for i := range f.s.VMs {
		if f.s.VMs[i].VMID == vmid {
			return &f.s.VMs[i]
		}
	}
	return nil
}

// guest checks permissions before revealing whether the VM exists.
func (f *Fake) guest(t *Token, r *http.Request, privs ...string) (*VM, *failure) {
	node, fail := f.node(r)
	if fail != nil {
		return nil, fail
	}
	vmid, err := strconv.Atoi(r.PathValue("vmid"))
	if err != nil || vmid < 1 {
		return nil, &failure{http.StatusBadRequest, "Parameter verification failed. vmid: type check ('integer') failed"}
	}
	if len(privs) == 0 {
		privs = []string{"VM.Audit"}
	}
	if fail := f.need(t, "/vms/"+strconv.Itoa(vmid), privs...); fail != nil {
		return nil, fail
	}
	vm := f.vm(vmid)
	if vm == nil || vm.Node != node {
		conf := path.Join("nodes", node, "qemu-server", strconv.Itoa(vmid)+".conf")
		return nil, &failure{http.StatusInternalServerError, fmt.Sprintf("Configuration file '%s' does not exist", conf)}
	}
	return vm, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// setIf sets k only when v is not empty: PVE leaves unset optional keys out.
func setIf(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}
