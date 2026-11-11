package pvefake

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

func (f *Fake) mutate(pattern string, h func(*Token, *http.Request) (any, *failure)) {
	f.mux.HandleFunc(strings.Replace(pattern, " /", " /api2/json/", 1),
		func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := r.ParseForm(); err != nil {
				reply(w, nil, &failure{http.StatusBadRequest, "Parameter verification failed. invalid form"})
				return
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			t := f.token(r.Header.Get("Authorization"))
			if t == nil {
				reply(w, nil, &failure{http.StatusUnauthorized, "authentication failure"})
				return
			}
			data, fail := h(t, r)
			reply(w, data, fail)
		})
}

func vmID(value string) (int, *failure) {
	id, err := strconv.Atoi(value)
	if err != nil || id < 100 || id > 999999999 {
		return 0, &failure{http.StatusBadRequest, "Parameter verification failed. vmid: invalid VM ID"}
	}
	return id, nil
}

func (f *Fake) nextID(_ *Token, r *http.Request) (any, *failure) {
	if value := r.URL.Query().Get("vmid"); value != "" {
		id, fail := vmID(value)
		if fail != nil {
			return nil, fail
		}
		if f.vm(id) != nil {
			msg := fmt.Sprintf("Parameter verification failed. vmid: VM %d already exists", id)
			return nil, &failure{http.StatusBadRequest, msg}
		}
		return id, nil
	}
	for id := 100; id < 1000000; id++ {
		if f.vm(id) == nil {
			return id, nil
		}
	}
	return nil, &failure{http.StatusInternalServerError, "unable to get any free VMID in range [100, 1000000]"}
}

func (f *Fake) cloneVM(t *Token, r *http.Request) (any, *failure) {
	for key, values := range r.Form {
		if len(values) != 1 || !slices.Contains(
			[]string{"newid", "name", "description", "pool", "full", "target", "storage"}, key) {
			return nil, &failure{http.StatusBadRequest, "Parameter verification failed. " + key + ": invalid parameter"}
		}
	}
	id, fail := vmID(r.Form.Get("newid"))
	if fail != nil {
		return nil, fail
	}
	vm, fail := f.guest(t, r, "VM.Clone")
	if fail != nil {
		return nil, fail
	}
	pool := r.Form.Get("pool")
	if !f.can(t, "/vms/"+strconv.Itoa(id), "VM.Allocate") {
		if pool == "" {
			return nil, f.need(t, "/vms/"+strconv.Itoa(id), "VM.Allocate")
		}
		if fail := f.need(t, "/pool/"+pool, "VM.Allocate"); fail != nil {
			return nil, fail
		}
	}
	if fail := f.cloneAccess(t, vm, r.Form.Get("storage")); fail != nil {
		return nil, fail
	}
	if !f.quorate {
		return nil, &failure{http.StatusInternalServerError, "cluster not ready - no quorum?"}
	}
	if vm.Config["lock"] != "" {
		return nil, &failure{http.StatusInternalServerError, "VM is locked (" + vm.Config["lock"] + ")"}
	}
	if f.vm(id) != nil {
		msg := fmt.Sprintf("unable to create VM %d: config file already exists", id)
		return nil, &failure{http.StatusInternalServerError, msg}
	}
	target := r.Form.Get("target")
	if target != "" {
		if online, ok := f.online[target]; !ok || !online {
			return nil, &failure{http.StatusInternalServerError, "target node unavailable"}
		}
	}
	full := r.Form.Get("full")
	if full != "" && full != "0" && full != "1" {
		return nil, &failure{http.StatusBadRequest, "Parameter verification failed. full: invalid boolean"}
	}
	if vm.Template && full != "1" && r.Form.Get("storage") != "" {
		return nil, &failure{http.StatusInternalServerError, "parameter 'storage' not allowed for linked clones"}
	}
	newVM := *vm
	newVM.VMID, newVM.Template, newVM.Status, newVM.Pool = id, false, "stopped", ""
	if target != "" {
		newVM.Node = target
	}
	newVM.Config, newVM.Snapshots = maps.Clone(vm.Config), nil
	if newVM.Config == nil {
		newVM.Config = map[string]string{}
	}
	newVM.Config["lock"] = "clone"
	newVM.Name = r.Form.Get("name")
	if newVM.Name == "" {
		newVM.Name = "Copy-of-VM-" + vm.Name
	}
	if value, ok := r.Form["description"]; ok {
		newVM.Config["description"] = value[0]
	}
	f.s.VMs = append(f.s.VMs, newVM)
	// PVE's qmclone task ID is the source VMID, not the new VMID.
	upid := f.cloneTask(t, vm.Node, vm.VMID, id, pool)
	return upid, nil
}

func (f *Fake) cloneAccess(t *Token, vm *VM, storage string) *failure {
	if sid, ok := vm.Config["vmstatestorage"]; ok {
		if fail := f.need(t, "/storage/"+sid, "Datastore.AllocateSpace"); fail != nil {
			return fail
		}
	}
	for key, value := range vm.Config {
		p := parseProperties(value)
		path, privilege := "/", "Sys.Console"
		switch strings.TrimRight(key, "0123456789") {
		case "net":
			bridge := p["bridge"]
			if bridge == "" {
				continue
			}
			path, privilege = "/sdn/zones/localnetwork/"+bridge, "SDN.Use"
		case "scsi", "sata", "ide", "virtio", "efidisk", "tpmstate":
			if p["media"] == "cdrom" {
				if p["file"] != "cdrom" {
					continue
				}
			} else {
				sid, _, ok := strings.Cut(p["file"], ":")
				if !ok {
					continue
				}
				if storage != "" {
					sid = storage
				}
				path, privilege = "/storage/"+sid, "Datastore.AllocateSpace"
			}
		default:
			continue
		}
		if fail := f.need(t, path, privilege); fail != nil {
			return fail
		}
	}
	return nil
}
