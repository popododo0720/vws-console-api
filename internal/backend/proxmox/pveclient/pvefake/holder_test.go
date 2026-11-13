package pvefake_test

import (
	"net/url"
	"testing"
)

func TestHolderDiskConfigCASAndOwnership(t *testing.T) {
	w := newWriteWorld(t)
	path := "/nodes/pve1/qemu/100/config"
	alloc := "/nodes/pve1/storage/ceph/content"
	body := "vmid=100&filename=vm-100-disk-9&size=1G"
	volid := w.write(t, "POST", alloc, body, "writer@pve!one", 200).(string)
	digest := w.config(t, "pve1", 100)["digest"].(string)
	form := url.Values{"scsi1": {volid + ",serial=0123456789abcdef0"}, "digest": {"stale"}}
	w.write(t, "PUT", path, form.Encode(), "writer@pve!one", 500)
	if w.config(t, "pve1", 100)["scsi1"] != nil {
		t.Fatal("stale digest attached a disk")
	}
	form.Set("digest", digest)
	w.write(t, "PUT", path, form.Encode(), auditor, 403)
	w.write(t, "PUT", path, form.Encode(), "writer@pve!one", 200)
	w.write(t, "PUT", path, form.Encode(), "writer@pve!one", 500)
	form.Set("digest", w.config(t, "pve1", 100)["digest"].(string))
	form.Set("scsi1", volid+",serial=0123456789abcdef1")
	w.write(t, "PUT", path, form.Encode(), "writer@pve!one", 200)
	if w.config(t, "pve1", 100)["scsi1"] != form.Get("scsi1") {
		t.Fatal("owned disk options were not updated")
	}
	form.Set("scsi1", "ceph:vm-100-disk-0")
	w.write(t, "PUT", path, form.Encode(), "writer@pve!one", 400)
	w.write(t, "POST", "/nodes/pve1/qemu", "vmid=110&tags=vws.holder&start=0", "writer@pve!one", 200)
	form = url.Values{"scsi0": {volid}}
	w.write(t, "PUT", "/nodes/pve1/qemu/110/config", form.Encode(), "writer@pve!one", 400)
	form.Set("scsi0", "ceph:missing")
	w.write(t, "PUT", "/nodes/pve1/qemu/110/config", form.Encode(), "writer@pve!one", 400)
	if w.config(t, "pve1", 110)["tags"] != "vws.holder" {
		t.Fatal("holder tag was not persisted during creation")
	}
}
