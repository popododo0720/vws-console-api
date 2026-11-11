package proxmox

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type inventoryVM struct{ pveclient.ClusterResource }

func (vm inventoryVM) Identity() string { return vm.ID }

func (b *Backend) ownsPool(s backend.Scope, pool string) bool {
	project := s.Account.String()
	if pool == "" {
		return project == b.cfg.DefaultProject
	}
	if mapped, ok := b.cfg.Pools[project]; ok {
		return mapped == pool
	}
	return project == pool
}

func (b *Backend) vmPage(
	ctx context.Context, s backend.Scope, page resource.PageRequest,
) (resource.Page[inventoryVM], error) {
	if b.cfg.DefaultProject != "" && s.Account.String() == b.cfg.DefaultProject {
		// PVE hides pool names without Pool.Audit; that must not look unpooled.
		permissions, err := b.client.AccessPermissions(ctx, "/pool")
		if err != nil {
			return resource.Page[inventoryVM]{}, fmt.Errorf("proxmox: check pool visibility: %w", err)
		}
		if permissions["/pool"]["Pool.Audit"] != 1 {
			return resource.Page[inventoryVM]{}, resource.Denied("proxmox: inventory requires Pool.Audit")
		}
	}
	rows, err := b.client.ClusterResources(ctx, pveclient.ResourceVM)
	if err != nil {
		return resource.Page[inventoryVM]{}, fmt.Errorf("proxmox: list VM inventory: %w", err)
	}
	var visible []inventoryVM
	for _, vm := range rows {
		if vm.Type != "qemu" || vm.Template == 1 || slices.Contains(strings.Split(vm.Tags, ";"), "vws.holder") {
			continue
		}
		if b.ownsPool(s, vm.Pool) {
			visible = append(visible, inventoryVM{vm})
		}
	}
	return networkPage(visible, page)
}

func option(text, key string) string {
	for _, part := range strings.Split(text, ",") {
		k, value, ok := strings.Cut(part, "=")
		if ok && k == key {
			return value
		}
	}
	return ""
}

func configUUID(cfg pveclient.VMConfig) string {
	if uuid := option(cfg.SMBIOS1, "uuid"); uuid != "" {
		return uuid
	}
	if cfg.Lock == "clone" || cfg.Lock == "create" {
		for line := range strings.SplitSeq(cfg.Description, "\n") {
			if uuid, ok := strings.CutPrefix(line, "vws:uuid "); ok {
				return strings.TrimSpace(uuid)
			}
		}
	}
	return ""
}

func (b *Backend) instance(
	ctx context.Context, ids IDs, vm inventoryVM, cfg pveclient.VMConfig,
) (resource.Instance, error) {
	ctime := option(cfg.Meta, "ctime")
	id, source, err := ids.Instance(VM{UUID: configUUID(cfg), VMID: vm.VMID, Ctime: ctime})
	if err != nil {
		return resource.Instance{}, err
	}
	tags, err := ReadTags(strings.Split(cfg.Tags, ";"), cfg.Description)
	if err != nil {
		return resource.Instance{}, err
	}
	image, err := ids.UnknownImage()
	if err != nil {
		return resource.Instance{}, err
	}
	for _, tag := range tags.System {
		if suffix, ok := strings.CutPrefix(tag, "vws.ami."); ok && len(suffix) == idHexLen {
			image, err = resource.Parse[resource.ImageID]("ami-" + suffix)
			if err != nil {
				return resource.Instance{}, fmt.Errorf("proxmox: image tag: %w", err)
			}
		}
	}
	state := resource.InstanceStopped
	switch {
	case cfg.Lock == "clone" || cfg.Lock == "create" || cfg.QMPStatus == "paused" || cfg.QMPStatus == "prelaunch":
		state = resource.InstancePending
	case vm.Status == "running":
		state = resource.InstanceRunning
	case vm.Status != "stopped":
		return resource.Instance{}, fmt.Errorf("proxmox: unknown VM status %q", vm.Status)
	}
	inst := resource.Instance{
		ID: id, ImageID: image, State: state, Tags: tags.User,
		InstanceType: NearestInstanceType(cfg.Cores*cfg.Sockets, cfg.Memory),
		Zone:         b.region + b.nodeLetter(ctx, vm.Node),
	}
	if ctime != "" {
		seconds, err := strconv.ParseInt(ctime, 10, 64)
		if err != nil || seconds < 0 {
			return resource.Instance{}, fmt.Errorf("proxmox: invalid meta.ctime %q", ctime)
		}
		inst.LaunchTime = time.Unix(seconds, 0).UTC()
	}
	if source != SourceUUID {
		slog.WarnContext(ctx, "fallback ID", slog.Int("vmid", vm.VMID), slog.String("id_source", string(source)))
	}
	return inst, nil
}

// DescribeInstances reads the caller's current pool without a cross-call cache.
func (b *Backend) DescribeInstances(
	ctx context.Context, s backend.Scope, q resource.InstanceQuery,
) (resource.Page[resource.Instance], error) {
	page, err := b.vmPage(ctx, s, q.Page)
	if err != nil {
		return resource.Page[resource.Instance]{}, err
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return resource.Page[resource.Instance]{}, err
	}
	out := resource.Page[resource.Instance]{NextToken: page.NextToken}
	for _, vm := range page.Items {
		cfg, err := b.client.VMConfig(ctx, pveclient.VM{Node: vm.Node, VMID: vm.VMID})
		var inst resource.Instance
		if err == nil {
			if cfg.Template == 1 || slices.Contains(strings.Split(cfg.Tags, ";"), "vws.holder") {
				continue
			}
			inst, err = b.instance(ctx, ids, vm, cfg)
		}
		if err != nil {
			if ctx.Err() != nil {
				return resource.Page[resource.Instance]{}, fmt.Errorf("proxmox: read instance config: %w", err)
			}
			slog.WarnContext(ctx, "skipping invalid VM", slog.Int("vmid", vm.VMID), slog.Any("error", err))
			continue
		}
		if (len(q.IDs) == 0 || slices.Contains(q.IDs, inst.ID)) &&
			(len(q.States) == 0 || slices.Contains(q.States, inst.State)) {
			inst.OwnerID = s.Account
			out.Items = append(out.Items, inst)
		}
	}
	return out, nil
}

func (b *Backend) nodeLetter(ctx context.Context, node string) string {
	for _, zone := range b.zones {
		if slices.Contains(zone.Nodes, node) {
			return zone.Letter
		}
	}
	if len(b.zones) != 0 {
		slog.WarnContext(ctx, "node has no registered zone; using a", slog.String("node", node))
	}
	return "a"
}

func (b *Backend) availabilityZones(ctx context.Context) ([]resource.RegionZone, error) {
	nodes, err := b.client.Nodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("proxmox: list availability zone nodes: %w", err)
	}
	zones := map[string]resource.RegionZone{}
	for _, zone := range b.zones {
		zones[zone.Letter] = resource.RegionZone{Nodes: slices.Clone(zone.Nodes)}
	}
	if len(zones) == 0 {
		zones["a"] = resource.RegionZone{}
	}
	for _, node := range nodes {
		letter := b.nodeLetter(ctx, node.Node)
		zone := zones[letter]
		if !slices.Contains(zone.Nodes, node.Node) {
			zone.Nodes = append(zone.Nodes, node.Node)
		}
		if node.Status == "online" {
			zone.State = "available"
		}
		zones[letter] = zone
	}
	var out []resource.RegionZone
	for letter, zone := range zones {
		zone.ZoneName, zone.ZoneID = b.region+letter, b.region+letter
		if zone.State == "" {
			zone.State = "impaired"
		}
		out = append(out, zone)
	}
	slices.SortFunc(out, func(a, b resource.RegionZone) int { return strings.Compare(a.ZoneName, b.ZoneName) })
	return out, nil
}
