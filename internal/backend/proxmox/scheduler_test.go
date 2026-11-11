package proxmox

import (
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func placementSnapshot(names ...string) []pveclient.ClusterResource {
	var rows []pveclient.ClusterResource
	for _, name := range names {
		rows = append(rows,
			pveclient.ClusterResource{Type: "node", Node: name, Status: "online", MaxMem: 8 << 30, MaxCPU: 4},
			pveclient.ClusterResource{Type: "storage", Node: name, Storage: "local-lvm", MaxDisk: 200 << 30},
		)
	}
	return rows
}

func placementRequest() PlacementRequest {
	return PlacementRequest{InstanceType: "vws.small", Storage: "local-lvm", RootSizeGiB: 10, Count: 1}
}

func TestScheduleFilters(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]pveclient.ClusterResource, *PlacementRequest, *SchedulerConfig) []pveclient.ClusterResource
		fit  bool
	}{
		{"defaults", nil, true},
		{"offline", func(r []pveclient.ClusterResource, _ *PlacementRequest, _ *SchedulerConfig) []pveclient.ClusterResource {
			r[0].Status = "offline"
			return r
		}, false},
		{"requested AZ", func(
			r []pveclient.ClusterResource, q *PlacementRequest, _ *SchedulerConfig,
		) []pveclient.ClusterResource {
			q.Zone = "pve-test-1b"
			return r
		}, false},
		{"default AZ", func(
			r []pveclient.ClusterResource, q *PlacementRequest, _ *SchedulerConfig,
		) []pveclient.ClusterResource {
			q.Zone = "pve-test-1a"
			return r
		}, true},
		{"local template elsewhere", func(
			r []pveclient.ClusterResource, q *PlacementRequest, _ *SchedulerConfig,
		) []pveclient.ClusterResource {
			q.TemplateNode = "pve2"
			return r
		}, false},
		{"local template here", func(
			r []pveclient.ClusterResource, q *PlacementRequest, _ *SchedulerConfig,
		) []pveclient.ClusterResource {
			q.TemplateNode = "pve1"
			return r
		}, true},
		{"storage invisible", func(
			r []pveclient.ClusterResource, _ *PlacementRequest, _ *SchedulerConfig,
		) []pveclient.ClusterResource {
			r[1].Node = "pve2"
			return r
		}, false},
		{"different storage", func(
			r []pveclient.ClusterResource, q *PlacementRequest, _ *SchedulerConfig,
		) []pveclient.ClusterResource {
			q.Storage = "other"
			return r
		}, false},
		{"disk exact headroom", func(
			r []pveclient.ClusterResource, _ *PlacementRequest, _ *SchedulerConfig,
		) []pveclient.ClusterResource {
			r[1].Disk = r[1].MaxDisk - 11<<30
			return r
		}, true},
		{"disk short one byte", func(
			r []pveclient.ClusterResource, _ *PlacementRequest, _ *SchedulerConfig,
		) []pveclient.ClusterResource {
			r[1].Disk = r[1].MaxDisk - 11<<30 + 1
			return r
		}, false},
		{"stopped VM memory reserved", func(
			r []pveclient.ClusterResource, _ *PlacementRequest, _ *SchedulerConfig,
		) []pveclient.ClusterResource {
			return append(r, pveclient.ClusterResource{Type: "qemu", Node: "pve1", Status: "stopped", MaxMem: 5<<30 + 1})
		}, false},
		{"memory exact fit", func(
			r []pveclient.ClusterResource, _ *PlacementRequest, _ *SchedulerConfig,
		) []pveclient.ClusterResource {
			return append(r, pveclient.ClusterResource{Type: "qemu", Node: "pve1", MaxMem: 5 << 30})
		}, true},
		{"host reserve", func(
			r []pveclient.ClusterResource, _ *PlacementRequest, c *SchedulerConfig,
		) []pveclient.ClusterResource {
			c.HostReserveMiB = 7169
			return r
		}, false},
		{"memory overcommit", func(
			r []pveclient.ClusterResource, q *PlacementRequest, c *SchedulerConfig,
		) []pveclient.ClusterResource {
			q.InstanceType, c.MemOvercommit = "vws.large", 2
			return r
		}, true},
		{"CPU exact overcommit", func(
			r []pveclient.ClusterResource, _ *PlacementRequest, _ *SchedulerConfig,
		) []pveclient.ClusterResource {
			return append(r, pveclient.ClusterResource{Type: "lxc", Node: "pve1", MaxCPU: 15})
		}, true},
		{"CPU overcommit full", func(
			r []pveclient.ClusterResource, _ *PlacementRequest, _ *SchedulerConfig,
		) []pveclient.ClusterResource {
			return append(r, pveclient.ClusterResource{Type: "qemu", Node: "pve1", MaxCPU: 16})
		}, false},
		{"CPU custom overcommit", func(
			r []pveclient.ClusterResource, _ *PlacementRequest, c *SchedulerConfig,
		) []pveclient.ClusterResource {
			c.CPUOvercommit = 1
			return append(r, pveclient.ClusterResource{Type: "qemu", Node: "pve1", MaxCPU: 4})
		}, false},
		{"templates consume no allocation", func(
			r []pveclient.ClusterResource, _ *PlacementRequest, _ *SchedulerConfig,
		) []pveclient.ClusterResource {
			return append(r, pveclient.ClusterResource{Type: "qemu", Node: "pve1", Template: 1, MaxCPU: 64, MaxMem: 128 << 30})
		}, true},
		{"other nodes consume no allocation", func(
			r []pveclient.ClusterResource, _ *PlacementRequest, _ *SchedulerConfig,
		) []pveclient.ClusterResource {
			return append(r, pveclient.ClusterResource{Type: "qemu", Node: "pve2", MaxCPU: 64, MaxMem: 128 << 30})
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, req, cfg := placementSnapshot("pve1"), placementRequest(), SchedulerConfig{}
			if tc.edit != nil {
				rows = tc.edit(rows, &req, &cfg)
			}
			plan, err := Schedule(rows, backend.ProxmoxRegion{Name: "pve-test-1"}, req, cfg)
			if tc.fit {
				if err != nil || !reflect.DeepEqual(plan, []Placement{{Node: "pve1", Storage: req.Storage}}) {
					t.Fatalf("plan = %+v, error = %v", plan, err)
				}
			} else if plan != nil || !resource.IsInsufficientInstanceCapacity(resource.AsError(err)) {
				t.Fatalf("want capacity error without a partial plan: %+v, %v", plan, err)
			}
		})
	}
}

func TestSchedulePolicies(t *testing.T) {
	for _, tc := range []struct {
		name, policy string
		memory       int64
		want         string
	}{
		{"spread uses lower fraction", "spread", 16 << 30, "pve2"},
		{"pack uses higher fraction", "pack", 16 << 30, "pve1"},
		{"spread breaks memory tie by VM count", "spread", 8 << 30, "pve2"},
		{"pack breaks memory tie by VM count", "pack", 8 << 30, "pve2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := placementSnapshot("pve1", "pve2")
			rows[2].MaxMem = tc.memory
			rows = append(rows, pveclient.ClusterResource{Type: "qemu", Node: "pve1"})
			plan, err := Schedule(rows, backend.ProxmoxRegion{}, placementRequest(), SchedulerConfig{Policy: tc.policy})
			if err != nil || len(plan) != 1 || plan[0].Node != tc.want {
				t.Fatalf("plan = %+v, error = %v; want %s", plan, err, tc.want)
			}
		})
	}
	for _, policy := range []string{"spread", "pack"} {
		t.Run(policy+" name tie", func(t *testing.T) {
			plan, err := Schedule(placementSnapshot("pve2", "pve1"), backend.ProxmoxRegion{},
				placementRequest(), SchedulerConfig{Policy: policy})
			if err != nil || len(plan) != 1 || plan[0].Node != "pve1" {
				t.Fatalf("name tie: %+v, %v", plan, err)
			}
		})
	}
}

func TestScheduleBatchAndZones(t *testing.T) {
	rows, req := placementSnapshot("pve3", "pve2", "pve1"), placementRequest()
	req.Count = 3
	region := backend.ProxmoxRegion{Name: "pve-test-1", Zones: []backend.Zone{{Letter: "b", Nodes: []string{"pve2"}}}}
	plan, err := Schedule(rows, region, req, SchedulerConfig{})
	if err != nil || !reflect.DeepEqual(plan, []Placement{
		{Node: "pve1", Storage: req.Storage}, {Node: "pve2", Storage: req.Storage}, {Node: "pve3", Storage: req.Storage},
	}) {
		t.Fatalf("spread batch: %+v, %v", plan, err)
	}
	req.Count, req.Zone = 1, "pve-test-1b"
	plan, err = Schedule(rows, region, req, SchedulerConfig{})
	if err != nil || len(plan) != 1 || plan[0].Node != "pve2" {
		t.Fatalf("registered AZ: %+v, %v", plan, err)
	}
	req.Count, req.Zone = 3, ""
	plan, err = Schedule(rows, region, req, SchedulerConfig{Policy: "pack"})
	if err != nil || len(plan) != 3 || plan[0].Node != "pve1" || plan[1].Node != "pve1" || plan[2].Node != "pve1" {
		t.Fatalf("pack batch: %+v, %v", plan, err)
	}
}

func TestScheduleOneNodeCatalogArithmetic(t *testing.T) {
	small, _ := ResolveInstanceType("vws.small")
	large, _ := ResolveInstanceType("vws.large")
	if small.MemoryMiB != 1024 || large.MemoryMiB != 8192 {
		t.Fatalf("catalog sizes changed: %+v, %+v", small, large)
	}
	rows, req := placementSnapshot("pve1"), placementRequest()
	req.Count = 2
	plan, err := Schedule(rows, backend.ProxmoxRegion{}, req, SchedulerConfig{})
	if err != nil || len(plan) != 2 {
		t.Fatalf("two 1 GiB VMs on 8 GiB minus 2 GiB reserve: %+v, %v", plan, err)
	}
	for _, placed := range plan {
		rows = append(rows, pveclient.ClusterResource{
			Type: "qemu", Node: placed.Node, MaxMem: int64(small.MemoryMiB) << 20, MaxCPU: float64(small.VCPUs),
		})
	}
	req.Count, req.InstanceType = 1, "t3.micro"
	if plan, err = Schedule(rows, backend.ProxmoxRegion{}, req, SchedulerConfig{}); err != nil || len(plan) != 1 {
		t.Fatalf("2 GiB allocated + 1 GiB <= 6 GiB usable: %+v, %v", plan, err)
	}
	req.InstanceType = large.Name
	for _, snapshot := range [][]pveclient.ClusterResource{rows, placementSnapshot("pve1")} {
		plan, err = Schedule(snapshot, backend.ProxmoxRegion{}, req, SchedulerConfig{})
		if plan != nil || !resource.IsInsufficientInstanceCapacity(resource.AsError(err)) {
			t.Fatalf("8 GiB exceeds 6 GiB usable: %+v, %v", plan, err)
		}
	}
}

func TestScheduleBatchCapacity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		count  int
		memory int64
		cpus   float64
		disk   int64
		shared int
	}{
		{"memory", 7, 8 << 30, 4, 200 << 30, 0},
		{"CPU", 3, 8 << 30, 0.5, 200 << 30, 0},
		{"local disk", 3, 8 << 30, 4, 21 << 30, 0},
		{"shared disk across nodes", 3, 8 << 30, 4, 21 << 30, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := placementSnapshot("pve1")
			if tc.shared == 1 {
				rows = append(rows, placementSnapshot("pve2")...)
			}
			for i := range rows {
				if rows[i].Type == "node" {
					rows[i].MaxMem, rows[i].MaxCPU = tc.memory, tc.cpus
				} else {
					rows[i].MaxDisk, rows[i].Shared = tc.disk, tc.shared
				}
			}
			req := placementRequest()
			req.Count = tc.count
			plan, err := Schedule(rows, backend.ProxmoxRegion{}, req, SchedulerConfig{})
			if plan != nil || !resource.IsInsufficientInstanceCapacity(resource.AsError(err)) {
				t.Fatalf("batch must reserve %s: %+v, %v", tc.name, plan, err)
			}
		})
	}
}

func TestSchedulePureReplay(t *testing.T) {
	rows, req := placementSnapshot("pve2", "pve1"), placementRequest()
	req.Count = 3
	region := backend.ProxmoxRegion{
		Name: "pve-test-1", Zones: []backend.Zone{{Letter: "a", Nodes: []string{"pve1", "pve2"}}},
	}
	before, err := json.Marshal([]any{rows, region, req})
	if err != nil {
		t.Fatal(err)
	}
	first, err := Schedule(rows, region, req, SchedulerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		replay, err := Schedule(rows, region, req, SchedulerConfig{})
		if err != nil || !reflect.DeepEqual(first, replay) {
			t.Fatalf("replay changed: %+v, %v", replay, err)
		}
	}
	after, err := json.Marshal([]any{rows, region, req})
	if err != nil || string(after) != string(before) {
		t.Fatalf("snapshot changed: %s, %v", after, err)
	}
	slices.Reverse(rows)
	reordered, err := Schedule(rows, region, req, SchedulerConfig{})
	if err != nil || !reflect.DeepEqual(first, reordered) {
		t.Fatalf("snapshot order changed plan: %+v, %v", reordered, err)
	}
}

func TestScheduleInvalidInputs(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  PlacementRequest
		cfg  SchedulerConfig
	}{
		{"unknown type", PlacementRequest{InstanceType: "unknown"}, SchedulerConfig{}},
		{"negative count", PlacementRequest{InstanceType: "vws.small", Count: -1}, SchedulerConfig{}},
		{"huge count", PlacementRequest{InstanceType: "vws.small", Count: math.MaxInt}, SchedulerConfig{}},
		{"missing storage", PlacementRequest{InstanceType: "vws.small", Count: 1}, SchedulerConfig{}},
		{"negative root", PlacementRequest{
			InstanceType: "vws.small", Count: 1, Storage: "local-lvm", RootSizeGiB: -1,
		}, SchedulerConfig{}},
		{"policy", placementRequest(), SchedulerConfig{Policy: "unknown"}},
		{"reserve", placementRequest(), SchedulerConfig{HostReserveMiB: -1}},
		{"memory ratio", placementRequest(), SchedulerConfig{MemOvercommit: -1}},
		{"CPU NaN", placementRequest(), SchedulerConfig{CPUOvercommit: math.NaN()}},
		{"memory infinity", placementRequest(), SchedulerConfig{MemOvercommit: math.Inf(1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := Schedule(placementSnapshot("pve1"), backend.ProxmoxRegion{}, tc.req, tc.cfg)
			if plan != nil || resource.CodeOf(err) != resource.CodeInvalidArgument {
				t.Fatalf("invalid request: %+v, %v", plan, err)
			}
		})
	}
	for _, rows := range [][]pveclient.ClusterResource{
		nil, {{Type: "node", Node: "pve1", Status: "online"}},
	} {
		plan, err := Schedule(rows, backend.ProxmoxRegion{}, placementRequest(), SchedulerConfig{})
		if plan != nil || !resource.IsInsufficientInstanceCapacity(resource.AsError(err)) {
			t.Fatalf("missing capacity: %+v, %v", plan, err)
		}
	}
	rows := placementSnapshot("pve1")
	rows = append(rows, pveclient.ClusterResource{Type: "qemu", Node: "pve1", MaxMem: -1})
	_, err := Schedule(rows, backend.ProxmoxRegion{}, placementRequest(), SchedulerConfig{})
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("negative VM allocation: %v", err)
	}
}
