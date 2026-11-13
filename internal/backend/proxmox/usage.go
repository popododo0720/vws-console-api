package proxmox

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// GetAllocation reads live pool membership and allocation, including holder disks.
func (b *Backend) GetAllocation(ctx context.Context, s backend.Scope, _ struct{}) (resource.Allocation, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Without Pool.Audit PVE hides pool names, which could expose another
	// project's allocation as unpooled capacity.
	permissions, err := b.client.AccessPermissions(ctx, "/pool")
	if err != nil {
		return resource.Allocation{}, fmt.Errorf("proxmox: usage pool visibility: %w", err)
	}
	if permissions["/pool"]["Pool.Audit"] != 1 {
		return resource.Allocation{}, resource.Denied("proxmox: usage requires Pool.Audit")
	}
	rows, err := b.client.ClusterResources(ctx, pveclient.ResourceVM)
	if err != nil {
		return resource.Allocation{}, fmt.Errorf("proxmox: usage inventory: %w", err)
	}
	var result resource.Allocation
	for _, vm := range rows {
		if vm.Type != "qemu" || vm.Template == 1 || !b.ownsPool(s, vm.Pool) {
			continue
		}
		if vm.Status == "unknown" {
			return resource.Allocation{}, &resource.Error{Code: resource.CodeUnavailable, Message: "allocation unavailable"}
		}
		result.DiskBytes += vm.MaxDisk
		if !slices.Contains(strings.Split(vm.Tags, ";"), "vws.holder") {
			result.VCPU += vm.MaxCPU
			result.MemoryBytes += vm.MaxMem
		}
	}
	return result, nil
}
