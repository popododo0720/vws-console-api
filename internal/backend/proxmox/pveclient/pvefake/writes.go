package pvefake

import (
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// SetNextIDs queues nextid answers, including duplicates or occupied IDs, to
// reproduce allocation races. Once exhausted, nextid scans the live inventory.
func (f *Fake) SetNextIDs(ids ...int) error {
	for _, id := range ids {
		if id < 100 || id > 999999999 {
			return fmt.Errorf("pvefake: invalid next ID %d", id)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextIDs = slices.Clone(ids)
	return nil
}

func (f *Fake) writeRoutes() {
	f.handleMethod(http.MethodPost, "/nodes/{node}/qemu/{vmid}/move_disk", f.moveDisk)
	f.handleMethod(http.MethodPost, "/nodes/{node}/storage/{storage}/content", f.allocateVolume)
	f.handleMethod(http.MethodPost, "/nodes/{node}/qemu/{vmid}/snapshot", f.writeSnapshot)
	f.handleMethod(http.MethodDelete, "/nodes/{node}/qemu/{vmid}/snapshot/{snapname}", f.writeSnapshot)
	f.handleMethod(http.MethodPost, "/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback",
		func(*Token, *http.Request) (any, *failure) {
			return nil, &failure{http.StatusForbidden, "snapshot rollback is forbidden"}
		})
	f.handleMethod(http.MethodPut, "/nodes/{node}/qemu/{vmid}/resize", f.resizeDisk)
	f.handleMethod(http.MethodPut, "/nodes/{node}/qemu/{vmid}/unlink", f.unlinkDisk)
	f.handle("/cluster/nextid", f.nextID)
	f.handleMethod(http.MethodPost, "/nodes/{node}/qemu/{vmid}/clone", f.cloneVM)
	f.handleMethod(http.MethodPost, "/nodes/{node}/qemu", f.createVM)
	f.handleMethod(http.MethodDelete, "/nodes/{node}/qemu/{vmid}", f.deleteVM)
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		f.handleMethod(method, "/nodes/{node}/qemu/{vmid}/config", f.writeConfig)
	}
}

func vmID(value string) (int, *failure) {
	id, err := strconv.Atoi(value)
	if err != nil || id < 100 || id > 999999999 {
		return 0, parameter("vmid", "value does not match a valid VM ID")
	}
	return id, nil
}

func (f *Fake) nextID(_ *Token, r *http.Request) (any, *failure) {
	for k, v := range r.URL.Query() {
		if k != "vmid" || len(v) != 1 {
			return nil, parameter(k, "unknown or repeated parameter")
		}
	}
	if value := r.URL.Query().Get("vmid"); r.URL.Query().Has("vmid") {
		id, fail := vmID(value)
		if fail != nil {
			return nil, fail
		}
		if f.vm(id) != nil {
			return nil, &failure{http.StatusInternalServerError, "VM " + value + " already exists"}
		}
		return id, nil
	}
	if len(f.nextIDs) > 0 {
		id := f.nextIDs[0]
		f.nextIDs = f.nextIDs[1:]
		return id, nil
	}
	for id := 100; id <= 999999999; id++ {
		if f.vm(id) == nil {
			return id, nil
		}
	}
	return nil, &failure{http.StatusInternalServerError, "no free VM ID"}
}

func writeForm(r *http.Request, keys ...string) *failure {
	form := *r
	form.Method = http.MethodPost // ParseForm otherwise ignores DELETE bodies.
	if err := form.ParseForm(); err != nil {
		return parameter("body", "unable to parse parameters")
	}
	r.Form = form.Form
	for k, v := range r.Form {
		if len(v) != 1 || !slices.Contains(keys, k) {
			return parameter(k, "unknown or repeated parameter")
		}
		if len(v[0]) > 10<<20 {
			return parameter(k, "value exceeds the form size limit")
		}
		if k == "digest" && len(v[0]) > 40 {
			return parameter(k, "value exceeds the digest length limit")
		}
		pattern := ""
		if k == "name" {
			pattern = `^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`
		}
		if k == "tags" {
			pattern = `^([a-zA-Z0-9_][a-zA-Z0-9_+.-]*|[,;[:space:]\x00])*$`
		}
		if pattern != "" {
			if valid, err := regexp.MatchString(pattern, v[0]); err != nil || !valid {
				return parameter(k, "value does not match the PVE format")
			}
		}
		if slices.Contains([]string{
			"full", "start", "purge", "destroy-unreferenced-disks", "protection", "vmstate", "force", "skiplock",
		}, k) && v[0] != "0" && v[0] != "1" {
			return parameter(k, "expected 0 or 1")
		}
	}
	return nil
}

func (f *Fake) writeGuest(t *Token, r *http.Request, priv string) (*VM, *failure) {
	node, fail := f.node(r)
	if fail != nil {
		return nil, fail
	}
	id, fail := vmID(r.PathValue("vmid"))
	if fail != nil {
		return nil, fail
	}
	if fail := f.need(t, "/vms/"+strconv.Itoa(id), priv); fail != nil {
		return nil, fail
	}
	vm := f.vm(id)
	if vm == nil || vm.Node != node {
		return nil, &failure{http.StatusInternalServerError, "Configuration file does not exist"}
	}
	if !f.quorate {
		return nil, &failure{http.StatusInternalServerError, "cluster not ready - no quorum?"}
	}
	if lock := vm.Config["lock"]; lock != "" {
		return nil, &failure{http.StatusInternalServerError, "VM is locked (" + lock + ")"}
	}
	return vm, nil
}

func (f *Fake) allocate(t *Token, id int, pool string) *failure {
	if pool != "" {
		exists := slices.Contains(f.s.Pools, pool)
		for _, vm := range f.s.VMs {
			exists = exists || vm.Pool == pool
		}
		if !exists {
			return parameter("pool", "pool does not exist")
		}
	}
	if !f.can(t, "/vms/"+strconv.Itoa(id), "VM.Allocate") {
		if pool == "" {
			return f.need(t, "/vms/"+strconv.Itoa(id), "VM.Allocate")
		}
		if fail := f.need(t, "/pool/"+pool, "VM.Allocate"); fail != nil {
			return fail
		}
	}
	if f.vm(id) != nil {
		return &failure{http.StatusInternalServerError, fmt.Sprintf("VM %d already exists", id)}
	}
	return nil
}

func (f *Fake) cloneVM(t *Token, r *http.Request) (any, *failure) {
	source, fail := f.writeGuest(t, r, "VM.Clone")
	if fail != nil {
		return nil, fail
	}
	if fail := writeForm(r, "newid", "pool", "full", "target", "description", "name"); fail != nil {
		return nil, fail
	}
	if r.Form.Get("full") == "0" && !source.Template {
		return nil, parameter("full", "linked clones require a template")
	}
	id, fail := vmID(r.Form.Get("newid"))
	if fail != nil {
		return nil, fail
	}
	if fail := f.allocate(t, id, r.Form.Get("pool")); fail != nil {
		return nil, fail
	}
	node := source.Node
	if target := r.Form.Get("target"); target != "" {
		if !f.online[target] {
			return nil, parameter("target", "unknown or offline node")
		}
		node = target
	}
	for k, disk := range source.Config {
		if configPrivilege(k) == "VM.Config.Network" {
			for part := range strings.SplitSeq(disk, ",") {
				if bridge, ok := strings.CutPrefix(part, "bridge="); ok {
					if fail := f.need(t, "/sdn/zones/localnetwork/"+bridge, "SDN.Use"); fail != nil {
						return nil, fail
					}
				}
			}
		}
		if configPrivilege(k) == "VM.Config.Disk" {
			storage, _, ok := strings.Cut(disk, ":")
			if ok {
				if fail := f.need(t, "/storage/"+storage, "Datastore.AllocateSpace"); fail != nil {
					return nil, fail
				}
			}
		}
	}
	clone := *source
	clone.VMID, clone.Node, clone.Pool = id, node, r.Form.Get("pool")
	clone.Template, clone.Status, clone.Snapshots = false, "stopped", nil
	clone.Config = maps.Clone(source.Config)
	if clone.Config == nil {
		clone.Config = map[string]string{}
	}
	for k, v := range clone.Config {
		clone.Config[k] = strings.ReplaceAll(v, fmt.Sprintf("vm-%d-", source.VMID), fmt.Sprintf("vm-%d-", id))
		if configPrivilege(k) == "VM.Config.Network" {
			device, options, _ := strings.Cut(v, ",")
			model, _, _ := strings.Cut(device, "=")
			clone.Config[k] = fmt.Sprintf("%s=02:00:%02x:%02x:%02x:%02x,%s",
				model, byte(id>>24), byte(id>>16), byte(id>>8), byte(id), options)
		}
	}
	if r.Form.Has("name") {
		clone.Name = r.Form.Get("name")
	}
	if r.Form.Has("description") {
		clone.Config["description"] = r.Form.Get("description")
	}
	clone.Config["lock"] = "clone"
	clone.Config["smbios1"] = fmt.Sprintf("uuid=00000000-0000-4000-8000-%012x", id)
	sourceID, sourceNode := source.VMID, source.Node
	f.s.VMs = append(f.s.VMs, clone)
	return f.submit(t, sourceNode, "qmclone", strconv.Itoa(sourceID), func() string {
		for i := range f.s.Storages {
			storage := &f.s.Storages[i]
			if storage.Node != node {
				continue
			}
			var copies []StorageContent
			for _, original := range f.s.Storages {
				if original.Node != sourceNode || original.Name != storage.Name {
					continue
				}
				for _, disk := range original.Content {
					if disk.VMID == sourceID {
						disk.VMID = id
						disk.VolID = strings.ReplaceAll(disk.VolID,
							fmt.Sprintf("vm-%d-", sourceID), fmt.Sprintf("vm-%d-", id))
						copies = append(copies, disk)
					}
				}
			}
			storage.Content = append(storage.Content, copies...)
		}
		return "OK"
	}, func(exit string) {
		if exit != "OK" {
			f.s.VMs = slices.DeleteFunc(f.s.VMs, func(vm VM) bool { return vm.VMID == id })
			return
		}
		delete(f.vm(id).Config, "lock")
	}), nil
}

func configPrivilege(key string) string {
	switch key {
	case "cores", "sockets", "cpu":
		return "VM.Config.CPU"
	case "memory", "balloon":
		return "VM.Config.Memory"
	case "smbios1":
		return "VM.Config.HWType"
	case "ciuser", "sshkeys", "ipconfig0":
		return "VM.Config.Cloudinit"
	}
	for _, bus := range []string{"scsi", "virtio", "sata", "ide", "net"} {
		if suffix, ok := strings.CutPrefix(key, bus); ok {
			if n, err := strconv.Atoi(suffix); err == nil && n >= 0 && suffix == strconv.Itoa(n) {
				if bus == "net" {
					return "VM.Config.Network"
				}
				return "VM.Config.Disk"
			}
		}
	}
	return "VM.Config.Options"
}

func setConfig(vm *VM, key, value string, remove bool) *failure {
	if key == "cores" || key == "memory" {
		n := 0
		if !remove {
			var err error
			n, err = strconv.Atoi(value)
			if err != nil {
				return parameter(key, "invalid integer")
			}
		}
		if key == "cores" {
			vm.MaxCPU = n
		} else {
			vm.MaxMem = int64(n) << 20
		}
	}
	switch key {
	case "name":
		vm.Name = value
	case "tags":
		vm.Tags = value
	default:
		if vm.Config == nil {
			vm.Config = map[string]string{}
		}
		if remove {
			delete(vm.Config, key)
		} else {
			vm.Config[key] = value
		}
	}
	return nil
}

func (f *Fake) writeConfig(t *Token, r *http.Request) (any, *failure) {
	allowed := []string{
		"digest", "delete", "name", "tags", "description", "protection",
		"cores", "sockets", "cpu", "memory", "balloon", "smbios1", "ciuser", "sshkeys", "ipconfig0",
	}
	for i := range 31 {
		allowed = append(allowed, fmt.Sprintf("scsi%d", i))
	}
	if fail := writeForm(r, allowed...); fail != nil {
		return nil, fail
	}
	keys := []string{}
	for k := range r.Form {
		if k != "digest" && k != "delete" {
			keys = append(keys, k)
		}
	}
	if r.Form.Has("delete") {
		keys = append(keys, strings.Split(r.Form.Get("delete"), ",")...)
	}
	var vm *VM
	for _, key := range keys {
		if !slices.Contains(allowed, key) || key == "digest" || key == "delete" {
			return nil, parameter("delete", "unsupported config key")
		}
		var fail *failure
		vm, fail = f.writeGuest(t, r, configPrivilege(key))
		if fail != nil {
			return nil, fail
		}
		if strings.HasPrefix(key, "scsi") {
			if !r.Form.Has(key) || vm.Config[key] != "" {
				return nil, parameter(key, "only attachment to an empty slot is modeled")
			}
			volume, _, _ := strings.Cut(r.Form.Get(key), ",")
			storage, _, ok := strings.Cut(volume, ":")
			disk := f.diskContent(vm.Node, volume)
			if !ok || disk == nil || disk.VMID != vm.VMID {
				return nil, parameter(key, "disk is not owned by this VM")
			}
			if fail := f.need(t, "/storage/"+storage, "Datastore.AllocateSpace"); fail != nil {
				return nil, fail
			}
		}
		if slices.Contains([]string{"cores", "sockets", "memory", "balloon"}, key) && r.Form.Has(key) {
			n, err := strconv.Atoi(r.Form.Get(key))
			if err != nil || n < 0 || n > 1<<40 || (n == 0 && key != "balloon") {
				return nil, parameter(key, "invalid integer")
			}
		}
	}
	if vm == nil {
		var fail *failure
		vm, fail = f.writeGuest(t, r, "VM.Config.Options")
		if fail != nil {
			return nil, fail
		}
	}
	if r.Form.Has("digest") && r.Form.Get("digest") != configRow(vm)["digest"] {
		return nil, &failure{http.StatusInternalServerError, "checksum mismatch (file change by other user?)"}
	}
	id := vm.VMID
	apply := func() string {
		vm := f.vm(id)
		if vm == nil {
			return "VM does not exist"
		}
		if lock := vm.Config["lock"]; lock != "" {
			return "VM is locked (" + lock + ")"
		}
		if r.Form.Has("digest") && r.Form.Get("digest") != configRow(vm)["digest"] {
			return "checksum mismatch (file change by other user?)"
		}
		for _, key := range strings.Split(r.Form.Get("delete"), ",") {
			if key != "" {
				if fail := setConfig(vm, key, "", true); fail != nil {
					return fail.msg
				}
			}
		}
		for k := range r.Form {
			if k != "digest" && k != "delete" {
				if fail := setConfig(vm, k, r.Form.Get(k), false); fail != nil {
					return fail.msg
				}
			}
		}
		return "OK"
	}
	if r.Method == http.MethodPost {
		return f.submit(t, vm.Node, "qmconfig", strconv.Itoa(id), apply), nil
	}
	apply()
	return nil, nil
}

func (f *Fake) createVM(t *Token, r *http.Request) (any, *failure) {
	node, fail := f.node(r)
	if fail != nil {
		return nil, fail
	}
	if fail := writeForm(r, "vmid", "pool", "start", "name", "tags",
		"description", "protection", "cores", "memory"); fail != nil {
		return nil, fail
	}
	if r.Form.Get("start") == "1" {
		return nil, parameter("start", "only stopped creation is modeled")
	}
	id, fail := vmID(r.Form.Get("vmid"))
	if fail != nil {
		return nil, fail
	}
	if fail := f.allocate(t, id, r.Form.Get("pool")); fail != nil {
		return nil, fail
	}
	if !f.quorate {
		return nil, &failure{http.StatusInternalServerError, "cluster not ready - no quorum?"}
	}
	vm := VM{
		VMID: id, Node: node, Pool: r.Form.Get("pool"), Status: "stopped",
		MaxCPU: 1, MaxMem: 512 << 20, Config: map[string]string{"cores": "1", "memory": "512"},
	}
	for _, k := range []string{"name", "tags", "description", "protection", "cores", "memory"} {
		if r.Form.Has(k) {
			if k == "cores" || k == "memory" {
				if n, err := strconv.Atoi(r.Form.Get(k)); err != nil || n < 1 || n > 1<<40 {
					return nil, parameter(k, "invalid integer")
				}
			}
			if fail := setConfig(&vm, k, r.Form.Get(k), false); fail != nil {
				return nil, fail
			}
		}
	}
	vm.Config["lock"] = "create"
	f.s.VMs = append(f.s.VMs, vm)
	return f.submit(t, node, "qmcreate", strconv.Itoa(id), func() string { return "OK" }, func(exit string) {
		if exit != "OK" {
			f.s.VMs = slices.DeleteFunc(f.s.VMs, func(vm VM) bool { return vm.VMID == id })
			return
		}
		delete(f.vm(id).Config, "lock")
	}), nil
}

func (f *Fake) deleteVM(t *Token, r *http.Request) (any, *failure) {
	vm, fail := f.writeGuest(t, r, "VM.Allocate")
	if fail != nil {
		return nil, fail
	}
	if fail := writeForm(r, "purge", "destroy-unreferenced-disks"); fail != nil {
		return nil, fail
	}
	if vm.Config["protection"] == "1" {
		return nil, &failure{http.StatusInternalServerError, "can't remove VM - protection mode enabled"}
	}
	id := vm.VMID
	if vm.Config == nil {
		vm.Config = map[string]string{}
	}
	vm.Config["lock"] = "destroy"
	return f.submit(t, vm.Node, "qmdestroy", strconv.Itoa(id), func() string {
		vm := f.vm(id)
		if vm == nil {
			return "VM does not exist"
		}
		if vm.Config["protection"] == "1" {
			return "can't remove VM - protection mode enabled"
		}
		if vm.Status == "running" {
			return "VM is running - destroy failed"
		}
		f.s.VMs = slices.DeleteFunc(f.s.VMs, func(vm VM) bool { return vm.VMID == id })
		for i := range f.s.Storages {
			f.s.Storages[i].Content = slices.DeleteFunc(f.s.Storages[i].Content,
				func(disk StorageContent) bool { return disk.VMID == id })
		}
		return "OK"
	}, func(_ string) {
		if vm := f.vm(id); vm != nil {
			delete(vm.Config, "lock")
		}
	}), nil
}
