package pvefake

import (
	"fmt"
	"maps"
	"math"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

func (f *Fake) submitVM(t *Token, vm *VM, kind, lock string, apply func(*VM) string) string {
	id := vm.VMID
	if vm.Config == nil {
		vm.Config = map[string]string{}
	}
	vm.Config["lock"] = lock
	return f.submit(t, vm.Node, kind, strconv.Itoa(id), func() string {
		vm := f.vm(id)
		if vm == nil {
			return "VM does not exist"
		}
		return apply(vm)
	}, func(_ string) {
		if vm := f.vm(id); vm != nil {
			delete(vm.Config, "lock")
		}
	})
}

func (f *Fake) writeSnapshot(t *Token, r *http.Request) (any, *failure) {
	vm, fail := f.writeGuest(t, r, "VM.Snapshot")
	if fail != nil {
		return nil, fail
	}
	keys := []string{"snapname", "description", "vmstate"}
	name, kind, lock := "", "qmsnapshot", "snapshot"
	if r.Method == http.MethodDelete {
		keys = []string{"force"}
		name, kind, lock = r.PathValue("snapname"), "qmdelsnapshot", "snapshot-delete"
	}
	if fail := writeForm(r, keys...); fail != nil {
		return nil, fail
	}
	if r.Method == http.MethodPost {
		name = r.Form.Get("snapname")
	}
	if !regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,39}$`).MatchString(name) || name == "current" {
		return nil, parameter("snapname", "invalid snapshot name")
	}
	index := slices.IndexFunc(vm.Snapshots, func(s Snapshot) bool { return s.Name == name })
	if r.Method == http.MethodPost && index >= 0 {
		return nil, &failure{http.StatusInternalServerError, "snapshot name already used"}
	}
	if r.Method == http.MethodDelete && index < 0 {
		return nil, &failure{http.StatusInternalServerError, "snapshot does not exist"}
	}
	if vm.Template {
		return nil, &failure{http.StatusInternalServerError, "cannot snapshot a template"}
	}
	return f.submitVM(t, vm, kind, lock, func(vm *VM) string {
		if r.Method == http.MethodDelete {
			parent := vm.Snapshots[index].Parent
			vm.Snapshots = slices.Delete(vm.Snapshots, index, index+1)
			for i := range vm.Snapshots {
				if vm.Snapshots[i].Parent == name {
					vm.Snapshots[i].Parent = parent
				}
			}
			return "OK"
		}
		parent := ""
		if len(vm.Snapshots) > 0 {
			parent = vm.Snapshots[len(vm.Snapshots)-1].Name
		}
		vm.Snapshots = append(vm.Snapshots, Snapshot{
			Name: name, Description: r.Form.Get("description"), Parent: parent, SnapTime: f.clock().Unix(),
			VMState: b2i(r.Form.Get("vmstate") == "1" && vm.Status == "running"),
		})
		return "OK"
	}), nil
}

func diskKey(key string, unused bool) bool {
	if key == "efidisk0" || key == "tpmstate0" {
		return true
	}
	for bus, count := range map[string]int{"ide": 4, "sata": 6, "scsi": 31, "virtio": 16, "unused": 256} {
		suffix, ok := strings.CutPrefix(key, bus)
		if !ok || (bus == "unused" && !unused) {
			continue
		}
		n, err := strconv.Atoi(suffix)
		return err == nil && n >= 0 && n < count && suffix == strconv.Itoa(n)
	}
	return false
}

func (f *Fake) diskContent(node, volid string) *StorageContent {
	for i := range f.s.Storages {
		storage := &f.s.Storages[i]
		if storage.Node == node {
			for j := range storage.Content {
				if storage.Content[j].VolID == volid {
					return &storage.Content[j]
				}
			}
		}
	}
	return nil
}

func (f *Fake) resizeDisk(t *Token, r *http.Request) (any, *failure) {
	vm, fail := f.writeGuest(t, r, "VM.Config.Disk")
	if fail != nil {
		return nil, fail
	}
	if fail := writeForm(r, "disk", "size", "digest", "skiplock"); fail != nil {
		return nil, fail
	}
	if r.Form.Get("skiplock") == "1" {
		return nil, &failure{http.StatusForbidden, "Only root can use this option"}
	}
	key, size := r.Form.Get("disk"), r.Form.Get("size")
	if !diskKey(key, false) {
		return nil, parameter("disk", "invalid disk ID")
	}
	if !regexp.MustCompile(`^\+?\d+(\.\d+)?[KMGT]?$`).MatchString(size) {
		return nil, parameter("size", "invalid disk size")
	}
	if r.Form.Has("digest") && r.Form.Get("digest") != configRow(vm)["digest"] {
		return nil, &failure{http.StatusInternalServerError, "checksum mismatch (file change by other user?)"}
	}
	volume, _, _ := strings.Cut(vm.Config[key], ",")
	disk := f.diskContent(vm.Node, volume)
	if disk == nil {
		return nil, &failure{http.StatusInternalServerError, "disk does not exist"}
	}
	unit := float64(1 << 30)
	if suffix := size[len(size)-1]; strings.ContainsRune("KMGT", rune(suffix)) {
		unit = math.Pow(1024, float64(strings.IndexByte("KMGT", suffix)+1))
		size = size[:len(size)-1]
	}
	n, err := strconv.ParseFloat(strings.TrimPrefix(size, "+"), 64)
	n *= unit
	if strings.HasPrefix(size, "+") {
		n += float64(disk.Size)
	}
	if err != nil || math.IsInf(n, 0) || n >= 1<<63 || n < 1 {
		return nil, parameter("size", "disk size out of range")
	}
	target := int64(math.Ceil(n))
	if target < disk.Size {
		return nil, &failure{http.StatusInternalServerError, "shrinking disks is not supported"}
	}
	return f.submitVM(t, vm, "qmresize", "disk", func(vm *VM) string {
		disk := f.diskContent(vm.Node, volume)
		disk.Size = target
		parts := strings.Split(vm.Config[key], ",")
		parts = slices.DeleteFunc(parts, func(s string) bool { return strings.HasPrefix(s, "size=") })
		size := strconv.FormatFloat(float64(target)/(1<<30), 'f', -1, 64) + "G"
		vm.Config[key] = strings.Join(parts, ",") + ",size=" + size
		return "OK"
	}), nil
}

func (f *Fake) unlinkDisk(t *Token, r *http.Request) (any, *failure) {
	vm, fail := f.writeGuest(t, r, "VM.Config.Disk")
	if fail != nil {
		return nil, fail
	}
	if fail := writeForm(r, "idlist", "force"); fail != nil {
		return nil, fail
	}
	keys := strings.FieldsFunc(r.Form.Get("idlist"), func(c rune) bool { return c == ',' || c == ';' || c == ' ' })
	if len(keys) == 0 {
		return nil, parameter("idlist", "missing disk IDs")
	}
	for _, key := range keys {
		if !diskKey(key, true) {
			return nil, parameter("idlist", "invalid disk ID")
		}
		if vm.Config[key] == "" {
			return nil, &failure{http.StatusInternalServerError, "disk does not exist"}
		}
	}
	if vm.Config["protection"] == "1" {
		return nil, &failure{http.StatusInternalServerError, "can't remove disk - protection mode enabled"}
	}
	config := maps.Clone(vm.Config)
	var remove []string
	for _, key := range slices.Compact(slices.Sorted(slices.Values(keys))) {
		volume, _, _ := strings.Cut(config[key], ",")
		delete(config, key)
		if strings.HasPrefix(key, "unused") || r.Form.Get("force") == "1" {
			remove = append(remove, volume)
		} else {
			i := 0
			for i < 256 && config[fmt.Sprintf("unused%d", i)] != "" {
				i++
			}
			if i == 256 {
				return nil, &failure{http.StatusInternalServerError, "no free unused disk entry"}
			}
			config[fmt.Sprintf("unused%d", i)] = volume
		}
	}
	vm.Config = config
	for i := range f.s.Storages {
		if f.s.Storages[i].Node == vm.Node {
			f.s.Storages[i].Content = slices.DeleteFunc(f.s.Storages[i].Content,
				func(disk StorageContent) bool { return slices.Contains(remove, disk.VolID) })
		}
	}
	return nil, nil
}
