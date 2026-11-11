package proxmox

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func volumeScenario() pvefake.Scenario {
	s := inventoryScenario()
	s.VMs[0].Tags = "vws.t.+name.web;vws.vt.01234567.+name.root;vws.vt.11234567.env.dev;vws.dot.11234567"
	s.VMs[0].Config["scsi0"] = "local:vm-100-disk-0,serial=0123456789abcdef0,size=999G"
	s.VMs[0].Config["scsi1"] = "local:vm-100-disk-1,serial=1123456789abcdef0"
	s.VMs[0].Config["ide2"] = "local:cloudinit,media=cdrom"
	s.VMs[0].Snapshots = []pvefake.Snapshot{
		{Name: "backup", Description: "backup\nvws:tags {\"Name\":\"backup\"}"},
		{Name: "memory", VMState: 1},
		{Name: "bad-tags", Description: "vws:tags {bad}"},
	}
	s.VMs = append(s.VMs, pvefake.VM{
		VMID: 101, Node: "pve1", Pool: "123456789012", Tags: "vws.holder;vws.vt.21234567.+name.free",
		Config: map[string]string{"virtio0": "local:vm-101-disk-0,serial=2123456789abcdef0"},
	}, pvefake.VM{
		VMID: 102, Node: "pve1", Pool: "999999999999",
		Config:    map[string]string{"scsi0": "local:vm-102-disk-0"},
		Snapshots: []pvefake.Snapshot{{Name: "foreign"}},
	}, pvefake.VM{
		VMID: 103, Node: "pve1", Pool: "123456789012", Config: map[string]string{"memory": "bad"},
	})
	s.Storages[0].Content = []pvefake.StorageContent{
		{VolID: "local:vm-100-disk-0", Content: "images", Format: "raw", Size: 8 << 30, VMID: 100},
		{VolID: "local:vm-100-disk-1", Content: "images", Format: "qcow2", Size: 12 << 30, VMID: 100},
		{VolID: "local:vm-101-disk-0", Content: "images", Format: "raw", Size: 3 << 30, VMID: 101},
		{VolID: "local:vm-102-disk-0", Content: "images", Format: "raw", Size: 99 << 30, VMID: 102},
	}
	return s
}

func TestVolumeIDsSurviveRestart(t *testing.T) {
	c, f := serve(t, volumeScenario())
	var first resource.Page[resource.Volume]
	for run := range 2 {
		b, err := New(t.Context(), c, registration(), RegionConfig{Storages: map[string]string{"gp3": "local"}})
		if err != nil {
			t.Fatal(err)
		}
		before := len(f.Requests())
		page, err := b.DescribeVolumes(t.Context(), inventoryScope(), resource.VolumeQuery{})
		if err != nil || len(page.Items) != 3 {
			t.Fatalf("volumes=%+v error=%v", page, err)
		}
		root, data, free := page.Items[0], page.Items[1], page.Items[2]
		if root.ID.String() != "vol-0123456789abcdef0" || root.SizeGiB != 8 || root.Format != "raw" ||
			root.State != resource.VolumeInUse || root.Device != "/dev/sda" || root.Tags["Name"] != "root" ||
			root.AttachState != resource.AttachmentAttached || !root.DeleteOnTermination || root.Type != resource.VolumeGP3 ||
			data.SizeGiB != 12 || data.Format != "qcow2" || data.Device != "/dev/sdf" || data.Tags["env"] != "dev" ||
			!data.DeleteOnTermination || data.InstanceID != root.InstanceID || root.InstanceID.IsZero() ||
			free.State != resource.VolumeAvailable || !free.InstanceID.IsZero() ||
			free.Device != "" || free.Tags["Name"] != "free" {
			t.Fatalf("projection=%+v", page.Items)
		}
		storageReads := 0
		for _, request := range f.Requests()[before:] {
			if strings.Contains(request, "/qemu/102/") {
				t.Fatalf("foreign VM was read: %s", request)
			}
			if strings.Contains(request, "/storage/local/content") {
				storageReads++
			}
		}
		if storageReads != 1 {
			t.Fatalf("storage reads=%d", storageReads)
		}
		if run == 0 {
			first = page
		} else if !reflect.DeepEqual(first, page) {
			t.Fatalf("restart changed volumes: %+v", page)
		}
	}
}

func TestVolumeVolnameFallback(t *testing.T) {
	s := volumeScenario()
	delete(s.VMs[0].Config, "scsi1")
	s.VMs[0].Config["scsi0"] = "local:vm-100-disk-0"
	b, f := networkBackend(t, s, RegionConfig{})
	ids, _ := NewIDs("test")
	id, source, _ := ids.Volume("", "local", "vm-100-disk-0")
	page, err := b.DescribeVolumes(t.Context(), inventoryScope(), resource.VolumeQuery{IDs: []resource.VolumeID{id}})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != id ||
		page.Items[0].IDSource != string(source) || source != SourceVolname {
		t.Fatalf("fallback=%+v error=%v", page, err)
	}
	if err := f.MoveVM(100, "other"); err != nil {
		t.Fatal(err)
	}
	_, err = b.DescribeVolumes(t.Context(), inventoryScope(), resource.VolumeQuery{IDs: []resource.VolumeID{id}})
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("moved VM still visible: %v", err)
	}
}

func TestSnapshotsStayInPool(t *testing.T) {
	b, f := networkBackend(t, volumeScenario(), RegionConfig{})
	before := len(f.Requests())
	page, err := b.DescribeSnapshots(t.Context(), inventoryScope(), resource.SnapshotQuery{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("snapshots=%+v error=%v", page, err)
	}
	ids, _ := NewIDs("test")
	id, _ := ids.Snapshot("5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10", "backup")
	snap := page.Items[0]
	if snap.ID != id || snap.VolumeID.String() != "vol-0123456789abcdef0" ||
		snap.VolumeSize != 8 || snap.State != resource.SnapshotCompleted || snap.Tags["Name"] != "backup" {
		t.Fatalf("snapshot=%+v", snap)
	}
	for _, request := range f.Requests()[before:] {
		if strings.Contains(request, "/qemu/102/") {
			t.Fatalf("foreign snapshot config read: %s", request)
		}
	}
	if err := f.MoveVM(100, "other"); err != nil {
		t.Fatal(err)
	}
	page, err = b.DescribeSnapshots(t.Context(), inventoryScope(), resource.SnapshotQuery{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("moved snapshots=%+v error=%v", page, err)
	}
}

func TestStoragePaging250VMs(t *testing.T) {
	s := inventoryScenario()
	s.VMs = nil
	for i := 100; i < 350; i++ {
		s.VMs = append(s.VMs, pvefake.VM{
			VMID: i, Node: "pve1", Pool: "123456789012",
			Config: map[string]string{
				"smbios1": fmt.Sprintf("uuid=5f0c3e9a-8b5d-4b8e-9a51-%012d", i),
				"scsi0":   fmt.Sprintf("local:vm-%d-disk-0,serial=%017x", i, i),
			},
			Snapshots: []pvefake.Snapshot{{Name: "backup"}},
		})
		s.Storages[0].Content = append(s.Storages[0].Content, pvefake.StorageContent{
			VolID: fmt.Sprintf("local:vm-%d-disk-0", i), Content: "images", Format: "raw", Size: 1 << 30, VMID: i,
		})
	}
	b, f := networkBackend(t, s, RegionConfig{})
	for _, kind := range []string{"volumes", "snapshots"} {
		t.Run(kind, func(t *testing.T) {
			var seen []string
			token := ""
			for {
				before := len(f.Requests())
				q := resource.PageRequest{Size: 100, Token: token}
				if kind == "volumes" {
					page, err := b.DescribeVolumes(t.Context(), inventoryScope(), resource.VolumeQuery{Page: q})
					if err != nil {
						t.Fatal(err)
					}
					for _, vol := range page.Items {
						seen = append(seen, vol.Identity())
					}
					token = page.NextToken
				} else {
					page, err := b.DescribeSnapshots(t.Context(), inventoryScope(), resource.SnapshotQuery{Page: q})
					if err != nil {
						t.Fatal(err)
					}
					for _, snap := range page.Items {
						seen = append(seen, snap.Identity())
					}
					token = page.NextToken
				}
				calls := 0
				for _, request := range f.Requests()[before:] {
					if strings.Contains(request, "/cluster/resources") {
						calls++
					}
				}
				if calls != 1 {
					t.Fatalf("cluster calls per page=%d", calls)
				}
				if token == "" {
					break
				}
				if len(seen) >= 250 {
					t.Fatal("cursor did not finish")
				}
			}
			slices.Sort(seen)
			if len(seen) != 250 || len(slices.Compact(seen)) != 250 {
				t.Fatalf("paging lost or repeated rows: %d", len(seen))
			}
		})
	}
}
