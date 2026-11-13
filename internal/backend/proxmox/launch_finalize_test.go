package proxmox

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func finalizeBackend(t *testing.T) (*launchWorld, backend.Mutation, resource.RunInstancesRequest) {
	t.Helper()
	w, m, req := launchBackend(t, false, func(s *pvefake.Scenario) {
		for i := range s.Roles {
			if s.Roles[i].ID == "Launch" {
				s.Roles[i].Privs = append(s.Roles[i].Privs, "VM.Config.CPU", "VM.Config.Memory",
					"VM.Config.Network", "VM.Config.Options", "VM.Config.Disk", "VM.Config.HWType", "VM.PowerMgmt")
			}
		}
		s.VMs[0].Config["smbios1"] += ",manufacturer=VWS"
		s.VMs[0].Config["scsi0"] += ",cache=writeback"
		s.VMs[0].Config["net0"] = "virtio=02:00:00:00:00:01,bridge=old,firewall=1"
		s.Roles = append(s.Roles, pvefake.Role{ID: "Network", Privs: []string{"SDN.Use"}})
		s.Tokens[0].ACL = append(s.Tokens[0].ACL, pvefake.ACE{Path: "/sdn/zones/localnetwork", Role: "Network"})
	})
	m.Pool = "managed"
	w.b.cfg.Pools = map[string]string{m.Account.String(): m.Pool}
	return w, m, req
}

func finalizePass(t *testing.T, b *Backend) error {
	t.Helper()
	finalizer, ok := any(b).(interface{ FinalizeLaunches(context.Context) error })
	if !ok {
		t.Fatal("backend cannot resume launch finalization")
	}
	return finalizer.FinalizeLaunches(t.Context())
}

func launchVM(t *testing.T, w *launchWorld, index int) pveclient.VM {
	t.Helper()
	id, err := strconv.Atoi(w.forms[index].Get("newid"))
	if err != nil {
		t.Fatal(err)
	}
	return pveclient.VM{Node: "pve1", VMID: id}
}

func assertFinalized(t *testing.T, w *launchWorld, m backend.Mutation, accepted resource.Accepted[resource.Instance]) {
	t.Helper()
	got, err := w.b.RecoverLaunch(t.Context(), m.Scope, m.Key, m.Fingerprint)
	if err != nil || got.Operation.State != resource.OperationSucceeded || got.Operation.ID != accepted.Operation.ID {
		t.Fatalf("recovered=%+v error=%v", got, err)
	}
	page, err := w.b.DescribeInstances(t.Context(), m.Scope, resource.InstanceQuery{})
	if err != nil || len(page.Items) != len(accepted.Items) {
		t.Fatalf("describe=%+v error=%v", page, err)
	}
	for i, item := range accepted.Items {
		if got.Instances[i] != item.ID || !slices.ContainsFunc(page.Items, func(v resource.Instance) bool {
			return v.ID == item.ID && v.State == resource.InstanceRunning
		}) {
			t.Fatalf("instance changed: accepted=%+v recovered=%+v describe=%+v", item, got, page)
		}
	}
	rows, err := w.b.client.ClusterResources(t.Context(), pveclient.ResourceVM)
	if err != nil || len(rows) != len(accepted.Items)+1 || len(w.f.PoolWriteViolations()) != 0 {
		t.Fatalf("VM count/ownership: rows=%+v error=%v violations=%v", rows, err, w.f.PoolWriteViolations())
	}
}

func TestFinalizeLaunchDoesNotBlockAccept(t *testing.T) {
	w, m, req := finalizeBackend(t)
	req.Count = 1
	first, err := w.b.RunInstances(t.Context(), m, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.f.SetTaskDelay(time.Hour); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	held, release := make(chan struct{}), make(chan struct{})
	signal := sync.OnceFunc(func() { close(held) })
	unblock := sync.OnceFunc(func() { w.elapsed.Add(int64(time.Hour)); close(release) })
	w.intercept = func(_ http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, ":qmstart:") && strings.HasSuffix(r.URL.Path, "/status") {
			signal()
			select {
			case <-release:
			case <-r.Context().Done():
				return true
			}
		}
		return false
	}
	finished, done := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(done)
		finished <- w.b.FinalizeLaunches(ctx)
	}()
	t.Cleanup(func() { cancel(); unblock(); <-done })
	select {
	case <-held:
	case <-ctx.Done():
		t.Fatal("finalizer did not reach the held start task")
	}
	next := m
	next.Key = strings.Repeat("b", 64)
	var accepted resource.Accepted[resource.Instance]
	var acceptErr error
	acceptedDone := make(chan struct{})
	go func() {
		defer close(acceptedDone)
		accepted, acceptErr = w.b.RunInstances(ctx, next, req)
	}()
	t.Cleanup(func() { cancel(); unblock(); <-acceptedDone })
	select {
	case <-acceptedDone:
	case <-ctx.Done():
		t.Fatal("RunInstances blocked behind finalization waiting for start")
	}
	if acceptErr != nil || len(accepted.Items) != 1 || accepted.Items[0].ID == first.Items[0].ID || len(w.forms) != 2 {
		t.Fatalf("concurrent accept=%+v error=%v clones=%d", accepted, acceptErr, len(w.forms))
	}
	before := len(w.f.Requests())
	if err := w.b.FinalizeLaunches(ctx); err != nil || len(w.f.Requests()) != before {
		t.Fatalf("overlapping pass reached PVE: %v", err)
	}
	unblock()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	recovered, err := w.b.RecoverLaunch(t.Context(), m.Scope, m.Key, m.Fingerprint)
	if err != nil || recovered.Operation.State != resource.OperationSucceeded ||
		recovered.Instances[0] != first.Items[0].ID {
		t.Fatalf("held launch did not complete: %+v %v", recovered, err)
	}
}

func TestFinalizeLaunchCrashWindows(t *testing.T) {
	for _, window := range []string{"W2", "W3", "W4", "W5", "bound alias"} {
		t.Run(window, func(t *testing.T) {
			w, m, req := finalizeBackend(t)
			req.Count = 3
			if window == "bound alias" {
				w.b.cfg.Pools = map[string]string{"operator-slot": m.Pool}
			}
			if window == "W2" {
				w.failAt = 3
				if _, err := w.b.RunInstances(t.Context(), m, req); err == nil {
					t.Fatal("third clone failure was ignored")
				}
				partial, err := w.b.RecoverLaunch(t.Context(), m.Scope, m.Key, m.Fingerprint)
				if err != nil || len(partial.Instances) != 2 {
					t.Fatalf("partial=%+v error=%v", partial, err)
				}
			}
			accepted, err := w.b.RunInstances(t.Context(), m, req)
			if err != nil || len(accepted.Items) != 3 {
				t.Fatalf("accept=%+v error=%v", accepted, err)
			}
			for i := range 2 {
				marker, _, _ := ReadLaunchMarker(w.forms[i].Get("description"))
				id, _, _ := newIDs(t, "test").Instance(VM{UUID: marker.UUID})
				if id != accepted.Items[i].ID {
					t.Fatal("retry replaced an allocated index")
				}
			}
			configWrites := 0
			if window == "W4" {
				w.intercept = func(_ http.ResponseWriter, r *http.Request) bool {
					if r.Method == http.MethodPut && r.ParseForm() == nil && r.Form.Has("smbios1") {
						configWrites++
					}
					return false
				}
				w.f.FailNext("qmstart", "injected start failure")
				if err := finalizePass(t, w.b); err == nil {
					t.Fatal("start failure was ignored")
				}
				cfg, err := w.b.client.VMConfig(t.Context(), launchVM(t, w, 0))
				marker, _, _ := ReadLaunchMarker(cfg.Description)
				if err != nil || configUUID(cfg) != marker.UUID || strings.Contains(cfg.Tags, "vws.k.") {
					t.Fatalf("config cut=%+v error=%v", cfg, err)
				}
			}
			if window == "W5" {
				w.intercept = func(rw http.ResponseWriter, r *http.Request) bool {
					if r.Method == http.MethodPut && r.ParseForm() == nil && r.Form.Has("tags") {
						rw.WriteHeader(http.StatusBadRequest)
						_, _ = rw.Write([]byte(`{"message":"lost completion write"}`))
						return true
					}
					return false
				}
				if err := finalizePass(t, w.b); err == nil {
					t.Fatal("completion write failure was ignored")
				}
				w.intercept = nil
			}
			w.b, err = New(t.Context(), w.b.client, Identity(w.b), w.b.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := finalizePass(t, w.b); err != nil {
				t.Fatal(err)
			}
			assertFinalized(t, w, m, accepted)
			if window == "W4" && configWrites != req.Count {
				t.Fatalf("replayed config writes=%d, want %d", configWrites, req.Count)
			}
			clones := len(w.forms)
			replayed, err := w.b.RunInstances(t.Context(), m, req)
			if err != nil || len(w.forms) != clones || !reflect.DeepEqual(replayed.Items, accepted.Items) {
				t.Fatalf("retry=%+v error=%v clones=%d", replayed, err, len(w.forms))
			}
			before := len(w.f.RequestMethods())
			if err := finalizePass(t, w.b); err != nil {
				t.Fatal(err)
			}
			for _, method := range w.f.RequestMethods()[before:] {
				if method != http.MethodGet {
					t.Fatalf("completed pass wrote %s", method)
				}
			}
			rows, err := w.b.client.OwnTasks(t.Context(), "pve1", url.Values{"typefilter": {"qmstart"}})
			successes := 0
			for _, row := range rows {
				if row.Status == "OK" {
					successes++
				}
			}
			if err != nil || successes != req.Count {
				t.Fatalf("successful starts=%d tasks=%+v error=%v", successes, rows, err)
			}
		})
	}
}

func TestFinalizeLaunchBoundaries(t *testing.T) {
	for _, boundary := range []string{"lock", "foreign pool", "foreign account", "malformed", "read only"} {
		t.Run(boundary, func(t *testing.T) {
			w, m, req := finalizeBackend(t)
			if boundary == "lock" {
				if err := w.f.SetTaskDelay(time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			accepted, err := w.b.RunInstances(t.Context(), m, req)
			if err != nil {
				t.Fatal(err)
			}
			vm := launchVM(t, w, 0)
			cfg, err := w.b.client.VMConfig(t.Context(), vm)
			if err != nil {
				t.Fatal(err)
			}
			switch boundary {
			case "foreign pool":
				if err := w.f.MoveVM(vm.VMID, "images"); err != nil {
					t.Fatal(err)
				}
			case "foreign account", "malformed":
				description := strings.ReplaceAll(cfg.Description, "acct="+m.Account.String(), "acct=999999999999")
				if boundary == "malformed" {
					description = "vws:v=broken"
				}
				fields := url.Values{"description": {description}}
				if err := w.b.client.WriteConfig(t.Context(), vm, cfg.Digest, fields); err != nil {
					t.Fatal(err)
				}
			case "read only":
				w.b.cfg.ReadOnly = true
			}
			var logs bytes.Buffer
			old := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			defer slog.SetDefault(old)
			before := len(w.f.Requests())
			err = finalizePass(t, w.b)
			if boundary == "read only" {
				if !resource.IsUnsupported(resource.AsError(err)) {
					t.Fatalf("read-only finalize=%v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			for _, request := range w.f.Requests()[before:] {
				if !strings.HasPrefix(request, "GET ") &&
					(boundary == "lock" || boundary == "read only" || strings.Contains(request, "/"+strconv.Itoa(vm.VMID)+"/")) {
					t.Fatalf("unsafe finalize write: %s", request)
				}
			}
			if boundary == "malformed" &&
				(!strings.Contains(logs.String(), "WARN") || strings.Contains(logs.String(), m.Account.String())) {
				t.Fatalf("malformed marker log=%s", logs.String())
			}
			if boundary == "lock" {
				w.elapsed.Add(int64(time.Hour))
				if err := w.f.SetTaskDelay(0); err != nil {
					t.Fatal(err)
				}
				if err := finalizePass(t, w.b); err != nil {
					t.Fatal(err)
				}
				assertFinalized(t, w, m, accepted)
			} else if boundary != "read only" {
				cfg, err := w.b.client.VMConfig(t.Context(), launchVM(t, w, 1))
				if err != nil || !strings.Contains(cfg.Tags, "vws.k.") || len(w.f.PoolWriteViolations()) != 0 {
					t.Fatalf("other VM not finalized: %+v %v", cfg, err)
				}
			}
		})
	}
}

func TestFinalizeLaunchConfigCAS(t *testing.T) {
	for _, stage := range []string{"config", "tags"} {
		for _, conflicts := range []int{1, 2} {
			t.Run(stage+strconv.Itoa(conflicts), func(t *testing.T) {
				w, m, req := finalizeBackend(t)
				req.Count = 1
				accepted, err := w.b.RunInstances(t.Context(), m, req)
				if err != nil {
					t.Fatal(err)
				}
				vm := launchVM(t, w, 0)
				before, _ := w.b.client.VMConfig(t.Context(), vm)
				before.SMBIOS1 += ",manufacturer=VWS"
				fields := url.Values{"smbios1": {before.SMBIOS1}}
				if err := w.b.client.WriteConfig(t.Context(), vm, before.Digest, fields); err != nil {
					t.Fatal(err)
				}
				writes := 0
				w.intercept = func(_ http.ResponseWriter, r *http.Request) bool {
					if r.Method != http.MethodPut || r.ParseForm() != nil || r.Form.Has("tags") != (stage == "tags") {
						return false
					}
					writes++
					if writes <= conflicts {
						cfg, readErr := w.b.client.VMConfig(r.Context(), vm)
						if readErr != nil || r.Form.Get("digest") != cfg.Digest {
							t.Errorf("stale read digest: %v", readErr)
						}
						fields := url.Values{"digest": {cfg.Digest}, "tags": {cfg.Tags + ";concurrent" + strconv.Itoa(writes)}}
						update := httptest.NewRequestWithContext(r.Context(), http.MethodPut, r.URL.String(),
							strings.NewReader(fields.Encode()))
						update.Header = r.Header.Clone()
						rec := httptest.NewRecorder()
						w.f.ServeHTTP(rec, update)
						if rec.Code != http.StatusOK {
							t.Errorf("concurrent update: %d %s", rec.Code, rec.Body)
						}
					}
					return false
				}
				err = finalizePass(t, w.b)
				if writes != 2 || (err != nil) != (conflicts == 2) {
					t.Fatalf("CAS attempts=%d error=%v", writes, err)
				}
				w.intercept = nil
				if conflicts == 2 {
					if err := finalizePass(t, w.b); err != nil {
						t.Fatal(err)
					}
				}
				assertFinalized(t, w, m, accepted)
				cfg, err := w.b.client.VMConfig(t.Context(), vm)
				marker, _, _ := ReadLaunchMarker(cfg.Description)
				serial, _ := newIDs(t, "test").RootVolumeSerial(marker.UUID)
				typ, _ := ResolveInstanceType(req.InstanceType)
				if err != nil || cfg.Description != before.Description || cfg.Cores != typ.VCPUs ||
					cfg.Memory != typ.MemoryMiB || cfg.Serial0 != "socket" || cfg.Agent != "1" ||
					option(cfg.Net0, "bridge") != "vmbr0" || option(cfg.Net0, "firewall") != "0" ||
					option(cfg.Net0, "virtio") != option(before.Net0, "virtio") ||
					option(cfg.SMBIOS1, "manufacturer") != "VWS" || option(cfg.Drives["scsi0"], "serial") != serial ||
					option(cfg.Drives["scsi0"], "cache") != "writeback" || !strings.Contains(cfg.Tags, "public") ||
					!strings.Contains(cfg.Tags, "concurrent"+strconv.Itoa(conflicts)) {
					t.Fatalf("finalized config=%+v error=%v", cfg, err)
				}
			})
		}
	}
}
