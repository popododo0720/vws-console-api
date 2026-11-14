package pvefake_test

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
)

func (w *taskWorld) targetDisks(t *testing.T) []pvefake.StorageContent {
	t.Helper()
	var env struct{ Data []pvefake.StorageContent }
	w.call(t, "GET", "/nodes/pve1/storage/target/content", "disk-reader@pve!one", 200, &env)
	return env.Data
}

func TestMoveDiskAndAllocationClientRestart(t *testing.T) {
	w := newWriteWorld(t)
	path := "/nodes/pve1/qemu/100/move_disk"
	digest := w.config(t, "pve1", 100)["digest"].(string)
	w.delay(t, 5)
	upid := w.write(t, "POST", path, "disk=scsi0&storage=target&digest="+digest+"&bwlimit=1024&format=qcow2",
		"writer@pve!one", 200).(string)
	if !strings.Contains(upid, ":qmmove:100:") || w.status(t, upid).Status != "running" ||
		w.config(t, "pve1", 100)["lock"] != "disk" || len(w.targetDisks(t)) != 0 {
		t.Fatal("disk moved before task completion")
	}
	w.write(t, "POST", path, "disk=scsi0&storage=target", "writer@pve!one", 500)
	w.now.Add(5)
	if st := w.status(t, upid); st.ExitStatus != "OK" {
		t.Fatal(st)
	}
	cfg := w.config(t, "pve1", 100)
	if cfg["unused0"] != "ceph:vm-100-disk-0" || cfg["lock"] != nil ||
		!strings.HasPrefix(cfg["scsi0"].(string), "target:vm-100-disk-0,") {
		t.Fatal(cfg)
	}
	if disks := w.targetDisks(t); len(disks) != 1 || disks[0].Format != "qcow2" || disks[0].Size != 8<<30 {
		t.Fatal(disks)
	}
	w.write(t, "POST", path, "disk=scsi0&storage=target", "writer@pve!one", 500)
	w.write(t, "POST", path, "disk=scsi0&storage=ceph&digest="+digest, "writer@pve!one", 500)
	alloc := "/nodes/pve1/storage/target/content"
	body := "vmid=100&filename=vm-100-disk-9.raw&size=512M"
	if volid := w.write(t, "POST", alloc, body, "writer@pve!one", 200); volid != "target:vm-100-disk-9.raw" {
		t.Fatal(volid)
	}
	w.write(t, "POST", alloc, body, "writer@pve!one", 500)
	srv := httptest.NewServer(w.f)
	t.Cleanup(srv.Close)
	for range 2 {
		c := client(t, srv, auditor, auditorKey)
		vm, err := c.VMConfig(t.Context(), pveclient.VM{Node: "pve1", VMID: 100})
		if err != nil || !strings.Contains(vm.Drives["scsi0"], "target:vm-100-disk-0") {
			t.Fatalf("recreated client config: %+v %v", vm, err)
		}
		var env struct{ Data []pvefake.StorageContent }
		w.call(t, "GET", alloc, "disk-reader@pve!one", 200, &env)
		if len(env.Data) != 2 || env.Data[1].Size != 512<<20 {
			t.Fatal(env.Data)
		}
	}
}

func TestMoveDiskTargetVMAndDelete(t *testing.T) {
	for _, remove := range []string{"0", "1"} {
		w := newWriteWorld(t)
		w.write(t, "POST", "/nodes/pve1/qemu", "vmid=110", "writer@pve!one", 200)
		digest := w.config(t, "pve1", 110)["digest"].(string)
		w.delay(t, 5)
		upid := w.write(t, "POST", "/nodes/pve1/qemu/100/move_disk",
			"disk=scsi0&storage=target&target-vmid=110&target-disk=virtio1&target-digest="+digest+"&delete="+remove,
			"writer@pve!one", 200).(string)
		if w.config(t, "pve1", 110)["lock"] != "disk" {
			t.Fatal("target VM not locked")
		}
		w.write(t, "PUT", "/nodes/pve1/qemu/110/config", "name=busy", "writer@pve!one", 500)
		w.now.Add(5)
		if st := w.status(t, upid); st.ExitStatus != "OK" {
			t.Fatal(st)
		}
		src, dst := w.config(t, "pve1", 100), w.config(t, "pve1", 110)
		if src["scsi0"] != nil || src["lock"] != nil || dst["lock"] != nil ||
			!strings.HasPrefix(dst["virtio1"].(string), "target:vm-110-disk-0,") {
			t.Fatalf("source=%v target=%v", src, dst)
		}
		if remove == "0" && (src["unused0"] == nil || len(w.disks(t)) != 1) ||
			remove == "1" && (src["unused0"] != nil || len(w.disks(t)) != 0) {
			t.Fatal("incorrect source retention", src)
		}
	}
	w := newWriteWorld(t)
	w.write(t, "POST", "/nodes/pve1/qemu", "vmid=110", "writer@pve!one", 200)
	upid := w.write(t, "POST", "/nodes/pve1/qemu/100/move_disk",
		"disk=scsi0&target-vmid=110&delete=1", "writer@pve!one", 200).(string)
	if w.status(t, upid).ExitStatus != "OK" || w.disks(t)[0].VMID != 110 {
		t.Fatal("target-only move failed")
	}
	w = newWriteWorld(t)
	w.write(t, "PUT", "/nodes/pve1/qemu/100/unlink", "idlist=scsi0", "writer@pve!one", 200)
	upid = w.write(t, "POST", "/nodes/pve1/qemu/100/move_disk",
		"disk=unused0&storage=target", "writer@pve!one", 200).(string)
	cfg := w.config(t, "pve1", 100)
	if w.status(t, upid).ExitStatus != "OK" || cfg["unused0"] != "target:vm-100-disk-0" ||
		cfg["unused1"] != "ceph:vm-100-disk-0" || len(w.disks(t)) != 1 {
		t.Fatal("moving an unused disk lost its retained source", cfg)
	}
}

func TestMoveDiskTaskFailure(t *testing.T) {
	w := newWriteWorld(t)
	w.write(t, "POST", "/nodes/pve1/qemu", "vmid=110", "writer@pve!one", 200)
	path, body := "/nodes/pve1/qemu/100/move_disk", "disk=scsi0&storage=target&target-vmid=110&delete=1"
	w.f.FailNext("qmmove", "storage full")
	w.write(t, "POST", path, body, auditor, 403)
	upid := w.write(t, "POST", path, body, "writer@pve!one", 200).(string)
	if w.status(t, upid).ExitStatus != "storage full" || len(w.targetDisks(t)) != 0 ||
		w.config(t, "pve1", 100)["lock"] != nil || w.config(t, "pve1", 110)["lock"] != nil ||
		w.config(t, "pve1", 100)["scsi0"] == nil || len(w.disks(t)) != 1 {
		t.Fatal("failed task changed inventory or retained locks")
	}
	upid = w.write(t, "POST", path, body, "writer@pve!one", 200).(string)
	if w.status(t, upid).ExitStatus != "OK" {
		t.Fatal("retry failed")
	}
	w.write(t, "POST", path, body, "writer@pve!one", 500)
}

func TestMoveAllocationACLAndParameters(t *testing.T) {
	move, alloc := "/nodes/pve1/qemu/100/move_disk", "/nodes/pve1/storage/target/content"
	for _, tc := range []struct{ path, body, privilege string }{
		{move, "disk=scsi0&storage=target", "VM.Config.Disk"},
		{move, "disk=scsi0&storage=target", "Datastore.AllocateSpace"},
		{alloc, "vmid=100&filename=vm-100-disk-1&size=1G", "VM.Config.Disk"},
	} {
		w := newWriteWorld(t, tc.privilege)
		w.write(t, "POST", tc.path, tc.body, "writer@pve!one", 403)
		w.write(t, "POST", tc.path, tc.body, auditor, 403)
		w.write(t, "POST", tc.path, tc.body, "unknown@pve!one", 401)
	}
	w := newWriteWorld(t)
	w.write(t, "POST", move, "disk=scsi0&target-vmid=101", "scoped@pve!one", 403)
	w.write(t, "POST", move, "disk=scsi0&storage=target", "scoped@pve!one", 403)
	for _, body := range []string{
		"", "storage=target", "disk=../bad&storage=target", "disk=scsi31&storage=target",
		"disk=scsi0", "disk=scsi0&storage=target&delete=2", "disk=scsi0&storage=target&bwlimit=-1",
		"disk=scsi0&storage=target&bwlimit=NaN", "disk=scsi0&storage=target&bwlimit=9223372036854775808",
		"disk=scsi0&storage=target&format=iso", "disk=scsi0&storage=target&target-disk=scsi1",
		"disk=scsi0&target-vmid=100", "disk=scsi0&target-vmid=99",
		"disk=scsi0&storage=target&target-disk=",
		"disk=scsi0&target-vmid=110&target-disk=net0", "disk=scsi0&storage=target&unknown=1",
		"disk=scsi0&disk=scsi1&storage=target",
		"disk=scsi0&storage=target&digest=" + strings.Repeat("a", 41),
	} {
		w.write(t, "POST", move, body, "writer@pve!one", 400)
	}
	for _, body := range []string{
		"", "vmid=99&filename=vm-99-disk-0&size=1G", "vmid=100&size=1G",
		"vmid=100&filename=../bad&size=1G", "vmid=100&filename=vm-101-disk-0&size=1G",
		"vmid=100&filename=vm-100-disk-0.raw&size=1G&format=qcow2",
		"vmid=100&filename=vm-100-disk-0&size=1G&format=iso",
		"vmid=100&filename=vm-100-disk-0&size=1G&unknown=1",
		"vmid=100&filename=vm-100-disk-0&size=1G&size=2G",
	} {
		w.write(t, "POST", alloc, body, "writer@pve!one", 400)
	}
	for _, size := range []string{"", "0", "-1", "1.5G", "1T", "9223372036854775808", "8589934592G", "1%00"} {
		w.write(t, "POST", alloc, "vmid=100&filename=vm-100-disk-0&size="+size, "writer@pve!one", 400)
	}
	for _, body := range []string{
		"disk=scsi1&storage=target", "disk=scsi0&storage=missing",
		"disk=scsi0&storage=target&digest=stale", "disk=scsi0&target-vmid=101",
	} {
		w.write(t, "POST", move, body, "writer@pve!one", 500)
	}
	w.write(t, "POST", "/nodes/pve1/qemu", "vmid=110", "writer@pve!one", 200)
	w.write(t, "POST", move, "disk=scsi0&target-vmid=110&target-digest="+strings.Repeat("a", 41), "writer@pve!one", 400)
	w.write(t, "POST", move, "disk=scsi0&target-vmid=110&target-digest=stale", "writer@pve!one", 500)
	if len(w.targetDisks(t)) != 0 || w.config(t, "pve1", 100)["lock"] != nil {
		t.Fatal("refusals changed state")
	}
	for i, size := range []string{"1", "1M", "1G"} {
		name := "vm-100-disk-" + strings.Repeat("1", i+1)
		w.write(t, "POST", alloc, "vmid=100&filename="+url.QueryEscape(name)+"&size="+size, "writer@pve!one", 200)
		if got := w.targetDisks(t)[i].Size; got != int64(1)<<(10*(i+1)) {
			t.Fatal(got)
		}
	}
	w.f.SetQuorate(false)
	w.write(t, "POST", move, "disk=scsi0&storage=target", "writer@pve!one", 500)
	w.write(t, "POST", alloc, "vmid=100&filename=vm-100-disk-7&size=1G", "writer@pve!one", 500)
}
