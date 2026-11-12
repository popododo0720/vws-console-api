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

func (f *Fake) storage(node, name string) *Storage {
	for i := range f.s.Storages {
		if s := &f.s.Storages[i]; s.Node == node && s.Name == name {
			return s
		}
	}
	return nil
}

func (f *Fake) allocateVolume(t *Token, r *http.Request) (any, *failure) {
	node, fail := f.node(r)
	if fail != nil {
		return nil, fail
	}
	name := r.PathValue("storage")
	if fail := f.need(t, "/storage/"+name, "Datastore.AllocateSpace"); fail != nil {
		return nil, fail
	}
	if fail := writeForm(r, "vmid", "filename", "size", "format"); fail != nil {
		return nil, fail
	}
	id, fail := vmID(r.Form.Get("vmid"))
	if fail != nil {
		return nil, fail
	}
	filename, format := r.Form.Get("filename"), r.Form.Get("format")
	pattern := fmt.Sprintf(`^vm-%d-disk-[0-9]+(\.(raw|qcow2|vmdk))?$`, id)
	if len(filename) > 255 || !regexp.MustCompile(pattern).MatchString(filename) {
		return nil, parameter("filename", "invalid disk image filename")
	}
	if _, ext, ok := strings.Cut(filename, "."); ok {
		if format != "" && format != ext {
			return nil, parameter("format", "different storage formats")
		}
		format = ext
	}
	if format == "" {
		format = "raw"
	}
	if !slices.Contains([]string{"raw", "qcow2", "vmdk"}, format) {
		return nil, parameter("format", "invalid image format")
	}
	size := r.Form.Get("size")
	if !regexp.MustCompile(`^[0-9]+[MG]?$`).MatchString(size) {
		return nil, parameter("size", "invalid volume size")
	}
	unit := int64(1024)
	if strings.HasSuffix(size, "M") {
		unit, size = 1<<20, strings.TrimSuffix(size, "M")
	} else if strings.HasSuffix(size, "G") {
		unit, size = 1<<30, strings.TrimSuffix(size, "G")
	}
	n, err := strconv.ParseInt(size, 10, 64)
	if err != nil || n < 1 || n > (1<<63-1)/unit {
		return nil, parameter("size", "volume size out of range")
	}
	storage := f.storage(node, name)
	if storage == nil {
		return nil, &failure{http.StatusInternalServerError, "storage does not exist"}
	}
	if !f.quorate {
		return nil, &failure{http.StatusInternalServerError, "cluster not ready - no quorum?"}
	}
	volid := name + ":" + filename
	if f.diskContent(node, volid) != nil {
		return nil, &failure{http.StatusInternalServerError, "volume already exists"}
	}
	storage.Content = append(storage.Content, StorageContent{
		VolID: volid, VMID: id, Size: n * unit, Format: format, Content: "images",
	})
	return volid, nil
}

func (f *Fake) moveDisk(t *Token, r *http.Request) (any, *failure) {
	vm, fail := f.writeGuest(t, r, "VM.Config.Disk")
	if fail != nil {
		return nil, fail
	}
	if fail := writeForm(r, "disk", "storage", "delete", "digest", "format", "bwlimit",
		"target-vmid", "target-disk", "target-digest"); fail != nil {
		return nil, fail
	}
	key, targetKey := r.Form.Get("disk"), r.Form.Get("target-disk")
	if !diskKey(key, true) {
		return nil, parameter("disk", "invalid disk ID")
	}
	if !r.Form.Has("target-disk") {
		targetKey = key
	}
	if !diskKey(targetKey, true) {
		return nil, parameter("target-disk", "invalid disk ID")
	}
	if r.Form.Has("delete") && r.Form.Get("delete") != "0" && r.Form.Get("delete") != "1" {
		return nil, parameter("delete", "expected 0 or 1")
	}
	if r.Form.Has("bwlimit") {
		if n, err := strconv.ParseInt(r.Form.Get("bwlimit"), 10, 64); err != nil || n < 0 {
			return nil, parameter("bwlimit", "invalid bandwidth limit")
		}
	}
	format, storage := r.Form.Get("format"), r.Form.Get("storage")
	if r.Form.Has("format") && !slices.Contains([]string{"raw", "qcow2", "vmdk"}, format) {
		return nil, parameter("format", "invalid image format")
	}
	target := vm
	if r.Form.Has("target-vmid") {
		id, fail := vmID(r.Form.Get("target-vmid"))
		if fail != nil {
			return nil, fail
		}
		if id == vm.VMID {
			return nil, parameter("target-vmid", "must differ from source VM")
		}
		if fail := f.need(t, "/vms/"+strconv.Itoa(id), "VM.Config.Disk"); fail != nil {
			return nil, fail
		}
		target = f.vm(id)
		if target == nil || target.Node != vm.Node {
			return nil, &failure{http.StatusInternalServerError, "target VM does not exist on this node"}
		}
		if target.Config["lock"] != "" {
			return nil, &failure{http.StatusInternalServerError, "target VM is locked"}
		}
	} else if storage == "" || r.Form.Has("target-disk") || r.Form.Has("target-digest") {
		return nil, parameter("target-vmid", "specify storage or a target VM")
	}
	if len(r.Form.Get("target-digest")) > 40 {
		return nil, parameter("target-digest", "value exceeds the digest length limit")
	}
	volume, _, _ := strings.Cut(vm.Config[key], ",")
	sourceStorage, _, _ := strings.Cut(volume, ":")
	if storage == "" {
		storage = sourceStorage
	}
	if fail := f.need(t, "/storage/"+storage, "Datastore.AllocateSpace"); fail != nil {
		return nil, fail
	}
	if f.storage(vm.Node, storage) == nil {
		return nil, &failure{http.StatusInternalServerError, "storage does not exist"}
	}
	check := func(vm, target *VM) string {
		if vm.Config[key] == "" || f.diskContent(vm.Node, volume) == nil ||
			strings.Split(vm.Config[key], ",")[0] != volume {
			return "disk does not exist"
		}
		if strings.Contains(vm.Config[key], "media=cdrom") {
			return "cannot move a CD-ROM"
		}
		for _, v := range []struct {
			vm  *VM
			key string
		}{{vm, "digest"}, {target, "target-digest"}} {
			if r.Form.Has(v.key) {
				copy := *v.vm
				copy.Config = maps.Clone(copy.Config)
				delete(copy.Config, "lock")
				if r.Form.Get(v.key) != configRow(&copy)["digest"] {
					return "checksum mismatch (file change by other user?)"
				}
			}
		}
		if target.VMID != vm.VMID {
			if target.Config[targetKey] != "" {
				return "target disk key is already in use"
			}
			if vm.Template || target.Template || vm.Config["protection"] == "1" {
				return "cannot move disk from protected or template VM"
			}
		} else if storage == sourceStorage && (format == "" || format == f.diskContent(vm.Node, volume).Format) {
			return "cannot move to the same storage with same format"
		}
		return ""
	}
	if msg := check(vm, target); msg != "" {
		return nil, &failure{http.StatusInternalServerError, msg}
	}
	sourceID, targetID := vm.VMID, target.VMID
	if target.Config == nil {
		target.Config = map[string]string{}
	}
	vm.Config["lock"], target.Config["lock"] = "disk", "disk"
	return f.submit(t, vm.Node, "qmmove", strconv.Itoa(sourceID), func() string {
		vm, target := f.vm(sourceID), f.vm(targetID)
		if vm == nil || target == nil {
			return "VM does not exist"
		}
		if msg := check(vm, target); msg != "" {
			return msg
		}
		dest := f.storage(vm.Node, storage)
		if dest == nil {
			return "storage does not exist"
		}
		unused := ""
		if r.Form.Get("delete") != "1" {
			for i := 0; i < 256; i++ {
				if k := fmt.Sprintf("unused%d", i); vm.Config[k] == "" {
					unused = k
					break
				}
			}
			if unused == "" {
				return "no free unused disk entry"
			}
		}
		disk := *f.diskContent(vm.Node, volume)
		disk.VMID = targetID
		if format != "" {
			disk.Format = format
		}
		for i := 0; ; i++ {
			disk.VolID = fmt.Sprintf("%s:vm-%d-disk-%d", storage, targetID, i)
			if f.diskContent(vm.Node, disk.VolID) == nil {
				break
			}
		}
		_, options, hasOptions := strings.Cut(vm.Config[key], ",")
		config := disk.VolID
		if hasOptions && !strings.HasPrefix(targetKey, "unused") {
			config += "," + options
		}
		delete(vm.Config, key)
		if unused != "" {
			vm.Config[unused] = volume
		} else {
			for i := range f.s.Storages {
				if f.s.Storages[i].Node == vm.Node {
					f.s.Storages[i].Content = slices.DeleteFunc(f.s.Storages[i].Content,
						func(d StorageContent) bool { return d.VolID == volume })
				}
			}
		}
		dest.Content = append(dest.Content, disk)
		target.Config[targetKey] = config
		return "OK"
	}, func(_ string) {
		for _, id := range []int{sourceID, targetID} {
			if vm := f.vm(id); vm != nil {
				delete(vm.Config, "lock")
			}
		}
	}), nil
}
