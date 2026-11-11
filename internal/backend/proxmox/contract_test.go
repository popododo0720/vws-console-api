package proxmox

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestContract(t *testing.T) {
	s := inventoryScenario()
	s.VMs[0].Pool = "tenant-pool"
	s.VMs[0].Config["scsi0"] = "local:vm-100-disk-0,serial=0123456789abcdef0"
	s.VMs[0].Config["scsi1"] = "local:vm-100-disk-1"
	s.VMs[0].Snapshots = []pvefake.Snapshot{{Name: "backup"}, {Name: "daily"}}
	s.VMs = append(s.VMs, pvefake.VM{
		VMID: 101, Node: "pve1", Pool: "tenant-pool", Status: "stopped",
		Config: map[string]string{
			"smbios1": "uuid=5f0c3e9a-8b5d-4b8e-9a51-000000000101",
			"scsi0":   "local:vm-101-disk-0,serial=1123456789abcdef0",
		},
		Snapshots: []pvefake.Snapshot{{Name: "backup"}},
	})
	s.Storages[0].Content = []pvefake.StorageContent{
		{VolID: "local:vm-100-disk-0", Content: "images", Format: "raw", Size: 8 << 30, VMID: 100},
		{VolID: "local:vm-100-disk-1", Content: "images", Format: "qcow2", Size: 12 << 30, VMID: 100},
		{VolID: "local:vm-101-disk-0", Content: "images", Format: "raw", Size: 8 << 30, VMID: 101},
	}
	s.Networks = []pvefake.Network{
		{Node: "pve1", Iface: "vmbr0", Type: "bridge", CIDR: "192.0.2.1/24"},
		{Node: "pve1", Iface: "vmbr1", Type: "bridge", CIDR: "198.51.100.1/24"},
	}
	c, _ := serve(t, s)
	reopen := func() *Backend {
		b, err := New(t.Context(), c, registration(), RegionConfig{
			ReadOnly: true, Pools: map[string]string{"123456789012": "tenant-pool"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	caps, err := reopen().RegionCapabilities(t.Context(), registration().Region.Name)
	if err != nil {
		t.Fatal(err)
	}
	backendtest.Run(t, func() backend.Set { return reopen().Set() }, caps)
	t.Run("IDStability", func(t *testing.T) {
		backendtest.IDStability(t, func() backend.Set { return reopen().Set() }, caps, inventoryScope())
	})
	t.Run("ReadTenancy", func(t *testing.T) {
		other, err := resource.Parse[resource.AccountID]("210987654321")
		if err != nil {
			t.Fatal(err)
		}
		backendtest.ReadTenancy(t, reopen().Set(), caps, inventoryScope(), backend.Scope{Account: other})
	})
}
