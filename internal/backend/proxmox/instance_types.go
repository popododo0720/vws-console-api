package proxmox

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// InstanceTypes returns the Proxmox default catalog, smallest first.
func InstanceTypes() []resource.InstanceType {
	return append(resource.InstanceTypes(),
		resource.InstanceType{Name: "vws.2xlarge", VCPUs: 16, MemoryMiB: 32768},
		resource.InstanceType{Name: "vws.4xlarge", VCPUs: 32, MemoryMiB: 65536},
		resource.InstanceType{Name: "vws.8xlarge", VCPUs: 64, MemoryMiB: 131072},
	)
}

// ResolveInstanceType accepts local names and the existing AWS aliases.
func ResolveInstanceType(name string) (resource.InstanceType, bool) {
	if alias, ok := resource.ComputeInstanceType(name); ok {
		name = alias
	}
	for _, typ := range InstanceTypes() {
		if typ.Name == name {
			return typ, true
		}
	}
	return resource.InstanceType{}, false
}

// NearestInstanceType matches total vCPUs and memory within 12.5% of a default type.
func NearestInstanceType(vcpus, memoryMiB int) string {
	if vcpus <= 0 || memoryMiB <= 0 {
		return "custom"
	}
	name, distance := "custom", 0
	for _, typ := range InstanceTypes() {
		diff := max(typ.MemoryMiB-memoryMiB, memoryMiB-typ.MemoryMiB)
		if typ.VCPUs == vcpus && diff <= typ.MemoryMiB/8 && (name == "custom" || diff < distance) {
			name, distance = typ.Name, diff
		}
	}
	return name
}

func validateInstanceTypes(cfg RegionConfig) error {
	if cfg.Scheduler.HostReserveMiB < 0 {
		return errors.New("proxmox: scheduler.host_reserve_mib must not be negative")
	}
	for _, name := range slices.Sorted(maps.Keys(cfg.InstanceTypes)) {
		size := cfg.InstanceTypes[name]
		typ, ok := ResolveInstanceType(name)
		if !ok || typ.Name != name {
			return fmt.Errorf("proxmox: instance_types.%s: unknown default type", name)
		}
		if (size.Cores != 0 && size.Cores != typ.VCPUs) ||
			(size.MemoryMiB != 0 && size.MemoryMiB != typ.MemoryMiB) {
			return fmt.Errorf("proxmox: instance_types.%s: must match default cores and memory_mib", name)
		}
	}
	return nil
}

func (b *Backend) instanceTypes(ctx context.Context) ([]resource.RegionInstanceType, error) {
	nodes, err := b.client.ClusterResources(ctx, pveclient.ResourceNode)
	if err != nil {
		return nil, fmt.Errorf("proxmox: instance types: list node capacity: %w", err)
	}
	reserve := b.cfg.Scheduler.HostReserveMiB
	if reserve == 0 {
		reserve = 2048
	}
	types := []resource.RegionInstanceType{}
	for _, typ := range InstanceTypes() {
		if b.cfg.InstanceTypes != nil {
			if _, ok := b.cfg.InstanceTypes[typ.Name]; !ok {
				continue
			}
		}
		for _, node := range nodes {
			if node.Type == "node" && float64(typ.VCPUs) <= node.MaxCPU &&
				int64(typ.MemoryMiB) <= node.MaxMem/(1<<20)-int64(reserve) {
				types = append(types, resource.RegionInstanceType{
					InstanceType: typ.Name, VCPUs: typ.VCPUs, MemoryMiB: typ.MemoryMiB,
				})
				break
			}
		}
	}
	return types, nil
}
