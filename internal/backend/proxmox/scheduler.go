package proxmox

import (
	"math"
	"slices"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// PlacementRequest describes one homogeneous batch. TemplateNode is empty for
// a template on shared storage; otherwise cloning is confined to that node.
type PlacementRequest struct {
	InstanceType string
	Zone         string
	TemplateNode string
	Storage      string
	RootSizeGiB  int
	Count        int
}

// Placement names the destination of one instance, in request order.
type Placement struct {
	Node    string
	Storage string
}

type placementNode struct {
	node     pveclient.ClusterResource
	storage  pveclient.ClusterResource
	memory   float64
	cpus     float64
	freeDisk float64
	vmCount  int
}

// Schedule computes a complete plan from a snapshot without clients or writes.
// It reserves only within this call; the caller must serialize planning and creation.
func Schedule(
	rows []pveclient.ClusterResource, region backend.ProxmoxRegion, req PlacementRequest, cfg SchedulerConfig,
) ([]Placement, error) {
	typ, ok := ResolveInstanceType(req.InstanceType)
	if !ok {
		return nil, resource.Invalid("instanceType", "Unknown instance type.")
	}
	if req.Count < 1 || req.Count > 10 {
		return nil, resource.Invalid("count", "Instance count must be between 1 and 10.")
	}
	if req.Storage == "" || req.RootSizeGiB <= 0 {
		return nil, resource.Invalid("storage", "Target storage and a positive root size are required.")
	}
	if cfg.Policy == "" {
		cfg.Policy = "spread"
	}
	if cfg.MemOvercommit == 0 {
		cfg.MemOvercommit = 1
	}
	if cfg.CPUOvercommit == 0 {
		cfg.CPUOvercommit = 4
	}
	if cfg.HostReserveMiB < 0 || (cfg.Policy != "spread" && cfg.Policy != "pack") ||
		!positiveFinite(cfg.MemOvercommit) || !positiveFinite(cfg.CPUOvercommit) {
		return nil, resource.Invalid("scheduler", "Invalid placement policy, reserve or overcommit.")
	}
	for _, row := range rows {
		if row.MaxMem < 0 || row.MaxCPU < 0 || math.IsNaN(row.MaxCPU) || math.IsInf(row.MaxCPU, 0) ||
			row.MaxDisk < 0 || row.Disk < 0 {
			return nil, resource.Invalid("resources", "Invalid cluster resource capacity.")
		}
	}
	nodes := placementNodes(rows, region, req)
	memory, cpus := float64(typ.MemoryMiB)*(1<<20), float64(typ.VCPUs)
	root := float64(req.RootSizeGiB) * (1 << 30)
	var plan []Placement
	for range req.Count {
		best := -1
		for i, node := range nodes {
			if node.freeDisk < root*1.1 || !nodeFits(node.node, node.memory+memory, node.cpus+cpus, cfg) {
				continue
			}
			if best < 0 || placementLess(node, nodes[best], memory, cfg) {
				best = i
			}
		}
		if best < 0 {
			return nil, resource.InsufficientInstanceCapacity()
		}
		chosen := &nodes[best]
		chosen.memory += memory
		chosen.cpus += cpus
		chosen.vmCount++
		plan = append(plan, Placement{Node: chosen.node.Node, Storage: req.Storage})
		for i := range nodes {
			if i == best || (chosen.storage.Shared == 1 && nodes[i].storage.Shared == 1) {
				nodes[i].freeDisk -= root
			}
		}
	}
	return plan, nil
}

func positiveFinite(n float64) bool {
	return n > 0 && !math.IsInf(n, 0) && !math.IsNaN(n)
}

func placementNodes(
	rows []pveclient.ClusterResource, region backend.ProxmoxRegion, req PlacementRequest,
) []placementNode {
	var nodes []placementNode
	for _, row := range rows {
		if row.Type != "node" || row.Status != "online" ||
			(req.TemplateNode != "" && req.TemplateNode != row.Node) {
			continue
		}
		letter := "a"
		for _, zone := range region.Zones {
			if slices.Contains(zone.Nodes, row.Node) {
				letter = zone.Letter
				break
			}
		}
		if req.Zone != "" && req.Zone != region.Name+letter {
			continue
		}
		for _, storage := range rows {
			if storage.Type != "storage" || storage.Storage != req.Storage || storage.Node != row.Node {
				continue
			}
			node := placementNode{
				node: row, storage: storage, freeDisk: float64(storage.MaxDisk) - float64(storage.Disk),
			}
			for _, vm := range rows {
				if (vm.Type == "qemu" || vm.Type == "lxc") && vm.Template != 1 && vm.Node == row.Node {
					node.memory += float64(vm.MaxMem)
					node.cpus += vm.MaxCPU
					node.vmCount++
				}
			}
			nodes = append(nodes, node)
			break
		}
	}
	return nodes
}

func placementLess(a, b placementNode, memory float64, cfg SchedulerConfig) bool {
	reserve := cfg.HostReserveMiB
	if reserve == 0 {
		reserve = 2048
	}
	aUse := (a.memory + memory) / (float64(a.node.MaxMem) - float64(reserve)*(1<<20))
	bUse := (b.memory + memory) / (float64(b.node.MaxMem) - float64(reserve)*(1<<20))
	if aUse != bUse {
		if cfg.Policy == "pack" {
			return aUse > bUse
		}
		return aUse < bUse
	}
	if a.vmCount != b.vmCount {
		return a.vmCount < b.vmCount
	}
	return a.node.Node < b.node.Node
}
