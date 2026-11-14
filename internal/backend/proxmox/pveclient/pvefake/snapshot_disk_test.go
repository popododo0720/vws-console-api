package pvefake_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
)

func (w *taskWorld) snapshots(t *testing.T) []pvefake.Snapshot {
	t.Helper()
	var env struct{ Data []pvefake.Snapshot }
	w.call(t, "GET", "/nodes/pve1/qemu/100/snapshot", auditor, 200, &env)
	return env.Data
}

func (w *taskWorld) disks(t *testing.T) []pvefake.StorageContent {
	t.Helper()
	var env struct{ Data []pvefake.StorageContent }
	w.call(t, "GET", "/nodes/pve1/storage/ceph/content", "disk-reader@pve!one", 200, &env)
	return env.Data
}

func TestSnapshotWritesAndClientRestart(t *testing.T) {
	w := newWriteWorld(t, "VM.Snapshot")
	w.delay(t, 5)
	path := "/nodes/pve1/qemu/100/snapshot"
	upid := w.write(t, "POST", path, "snapname=before&description=saved&vmstate=1", "writer@pve!one", 200).(string)
	if !strings.Contains(upid, ":qmsnapshot:100:") || w.status(t, upid).Status != "running" ||
		len(w.snapshots(t)) != 1 || w.config(t, "pve1", 100)["lock"] != "snapshot" {
		t.Fatal("snapshot task did not hold its lock")
	}
	w.write(t, "POST", path, "snapname=busy", "writer@pve!one", 500)
	w.now.Add(5)
	if st := w.status(t, upid); st.ExitStatus != "OK" {
		t.Fatal(st)
	}
	snaps := w.snapshots(t)
	if len(snaps) != 2 || snaps[1].Name != "before" || snaps[1].Description != "saved" ||
		snaps[1].VMState != 1 || snaps[1].SnapTime != w.now.Load() {
		t.Fatal(snaps)
	}
	w.write(t, "POST", path, "snapname=before", "writer@pve!one", 500)
	w.delay(t, 0)
	w.write(t, "POST", path, "snapname=after", "writer@pve!one", 200)
	if snaps := w.snapshots(t); snaps[2].Parent != "before" {
		t.Fatal(snaps)
	}
	w.delay(t, 5)
	upid = w.write(t, "DELETE", path+"/before", "force=1", "writer@pve!one", 200).(string)
	if !strings.Contains(upid, ":qmdelsnapshot:100:") || w.status(t, upid).Status != "running" {
		t.Fatal(upid)
	}
	w.now.Add(5)
	if w.status(t, upid).ExitStatus != "OK" || w.config(t, "pve1", 100)["lock"] != nil {
		t.Fatal("snapshot delete did not finish")
	}
	srv := httptest.NewServer(w.f)
	t.Cleanup(srv.Close)
	for range 2 {
		c := client(t, srv, auditor, auditorKey)
		snaps, err := c.Snapshots(t.Context(), pveclient.VM{Node: "pve1", VMID: 100})
		if err != nil || len(snaps) != 2 || snaps[1].Name != "after" || snaps[1].Parent != "" {
			t.Fatalf("recreated client snapshots: %+v %v", snaps, err)
		}
	}
	w.write(t, "DELETE", path+"/before", "", "writer@pve!one", 500)
	w.write(t, "POST", "/nodes/pve1/qemu/102/snapshot", "snapname=missing", "writer@pve!one", 500)
}

func TestResizeAndUnlinkReadBack(t *testing.T) {
	w := newWriteWorld(t, "VM.Config.Disk")
	path := "/nodes/pve1/qemu/100"
	digest := w.config(t, "pve1", 100)["digest"].(string)
	w.delay(t, 5)
	upid := w.write(t, "PUT", path+"/resize", "disk=scsi0&size=%2B2G&digest="+digest,
		"writer@pve!one", 200).(string)
	if !strings.Contains(upid, ":qmresize:100:") || w.status(t, upid).Status != "running" ||
		w.disks(t)[0].Size != 8<<30 {
		t.Fatal("resize applied before task completion")
	}
	w.write(t, "PUT", path+"/unlink", "idlist=scsi0", "writer@pve!one", 500)
	w.now.Add(5)
	if w.status(t, upid).ExitStatus != "OK" || w.disks(t)[0].Size != 10<<30 ||
		!strings.Contains(w.config(t, "pve1", 100)["scsi0"].(string), ",size=10G") {
		t.Fatal("resize did not update config and storage")
	}
	w.write(t, "PUT", path+"/resize", "disk=scsi0&size=12G&digest="+digest, "writer@pve!one", 500)
	w.write(t, "PUT", path+"/resize", "disk=scsi0&size=9G", "writer@pve!one", 500)
	w.delay(t, 0)
	for _, size := range []string{"10.5G", "11264M", "11534336K", "12", "%2B0"} {
		upid = w.write(t, "PUT", path+"/resize", "disk=scsi0&size="+size, "writer@pve!one", 200).(string)
		if st := w.status(t, upid); st.ExitStatus != "OK" {
			t.Fatal(st)
		}
	}
	if w.disks(t)[0].Size != 12<<30 {
		t.Fatal(w.disks(t))
	}
	if data := w.write(t, "PUT", path+"/unlink", "idlist=scsi0,scsi0", "writer@pve!one", 200); data != nil {
		t.Fatalf("unlink must return null, got %v", data)
	}
	cfg := w.config(t, "pve1", 100)
	if cfg["scsi0"] != nil || cfg["unused0"] != "ceph:vm-100-disk-0" || len(w.disks(t)) != 1 {
		t.Fatal(cfg)
	}
	w.write(t, "PUT", path+"/unlink", "idlist=unused0", "writer@pve!one", 200)
	if w.config(t, "pve1", 100)["unused0"] != nil || len(w.disks(t)) != 0 {
		t.Fatal("unused unlink did not remove the volume")
	}
	w.write(t, "PUT", path+"/unlink", "idlist=unused0", "writer@pve!one", 500)
	force := newWriteWorld(t, "VM.Config.Disk")
	force.write(t, "PUT", path+"/unlink", "idlist=scsi0&force=1", "writer@pve!one", 200)
	if len(force.disks(t)) != 0 || force.config(t, "pve1", 100)["unused0"] != nil {
		t.Fatal("force unlink retained the disk")
	}
}

func TestSnapshotDiskACLAndParameters(t *testing.T) {
	for _, tc := range []struct{ method, suffix, body, privilege string }{
		{"POST", "/snapshot", "snapname=one", "VM.Config.Disk"},
		{"DELETE", "/snapshot/one", "", "VM.Config.Disk"},
		{"PUT", "/resize", "disk=scsi0&size=10G", "VM.Snapshot"},
		{"PUT", "/unlink", "idlist=scsi0", "VM.Snapshot"},
	} {
		w := newWriteWorld(t)
		path := "/nodes/pve1/qemu/100" + tc.suffix
		w.write(t, tc.method, path, tc.body, auditor, 403)
		limited := newWriteWorld(t, tc.privilege)
		limited.write(t, tc.method, path, tc.body, "writer@pve!one", 403)
		w.write(t, tc.method, path, tc.body, "unknown@pve!one", 401)
		w.write(t, tc.method, "/nodes/pve2/qemu/101"+tc.suffix, tc.body, "scoped@pve!one", 403)
		w.f.SetQuorate(false)
		w.write(t, tc.method, path, tc.body, "writer@pve!one", 500)
	}
	for _, tc := range []struct{ method, suffix, body string }{
		{"POST", "/snapshot", ""},
		{"POST", "/snapshot", "snapname=current"},
		{"POST", "/snapshot", "snapname=../bad"},
		{"POST", "/snapshot", "snapname=" + strings.Repeat("a", 41)},
		{"POST", "/snapshot", "snapname=one&vmstate=2"},
		{"POST", "/snapshot", "snapname=one&snapname=two"},
		{"DELETE", "/snapshot/current", ""},
		{"DELETE", "/snapshot/one", "force=2"},
		{"DELETE", "/snapshot/one", "snapname=two"},
		{"PUT", "/resize", "disk=scsi0"},
		{"PUT", "/resize", "size=10G"},
		{"PUT", "/resize", "disk=unused0&size=10G"},
		{"PUT", "/resize", "disk=scsi31&size=10G"},
		{"PUT", "/resize", "disk=net0&size=10G"},
		{"PUT", "/resize", "disk=scsi0&size=-1G"},
		{"PUT", "/resize", "disk=scsi0&size=1e10"},
		{"PUT", "/resize", "disk=scsi0&size=99999999999999999999T"},
		{"PUT", "/resize", "disk=scsi0&size=10G&unknown=1"},
		{"PUT", "/resize", "disk=scsi0&size=10G&digest=" + strings.Repeat("a", 41)},
		{"PUT", "/unlink", ""},
		{"PUT", "/unlink", "idlist=net0"},
		{"PUT", "/unlink", "idlist=unused256"},
		{"PUT", "/unlink", "idlist=scsi0&force=2"},
	} {
		w := newWriteWorld(t)
		w.write(t, tc.method, "/nodes/pve1/qemu/100"+tc.suffix, tc.body, "writer@pve!one", 400)
		if cfg := w.config(t, "pve1", 100); cfg["lock"] != nil || cfg["scsi0"] == nil {
			t.Fatal("refused parameters changed VM", cfg)
		}
	}
	w := newWriteWorld(t)
	w.write(t, "PUT", "/nodes/pve1/qemu/100/resize", "disk=scsi0&size=10G&skiplock=1", "writer@pve!one", 403)
	w.write(t, "PUT", "/nodes/pve1/qemu/100/unlink", "idlist=scsi0,scsi1", "writer@pve!one", 500)
	if w.config(t, "pve1", 100)["scsi0"] == nil {
		t.Fatal("unlink partially applied a refused list")
	}
}

func TestSnapshotDiskTaskFailures(t *testing.T) {
	for _, tc := range []struct{ method, suffix, body, kind string }{
		{"POST", "/snapshot", "snapname=one", "qmsnapshot"},
		{"DELETE", "/snapshot/one", "force=1", "qmdelsnapshot"},
		{"PUT", "/resize", "disk=scsi0&size=10G", "qmresize"},
	} {
		w := newWriteWorld(t)
		path := "/nodes/pve1/qemu/100"
		w.write(t, "POST", path+"/snapshot", "snapname=one", "writer@pve!one", 200)
		body := tc.body
		if tc.kind == "qmsnapshot" {
			body = "snapname=two"
		}
		w.f.FailNext(tc.kind, "storage full")
		w.write(t, tc.method, path+tc.suffix, body, auditor, 403)
		upid := w.write(t, tc.method, path+tc.suffix, body, "writer@pve!one", 200).(string)
		if w.status(t, upid).ExitStatus != "storage full" || w.config(t, "pve1", 100)["lock"] != nil ||
			len(w.snapshots(t)) != 2 || w.disks(t)[0].Size != 8<<30 {
			t.Fatalf("%s failure changed state", tc.kind)
		}
		upid = w.write(t, tc.method, path+tc.suffix, body, "writer@pve!one", 200).(string)
		if st := w.status(t, upid); st.ExitStatus != "OK" {
			t.Fatal(st)
		}
	}
}
