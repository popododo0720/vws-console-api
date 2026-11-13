package proxmox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type launchInventory struct {
	vms   []inventoryVM
	stale bool
}

// FinalizeLaunches resumes unfinished clones in the managed pools.
func (b *Backend) FinalizeLaunches(ctx context.Context, fence func(context.Context) error) error {
	if b.cfg.ReadOnly {
		return resource.Unsupported("FinalizeLaunches", "read-only")
	}
	if !b.finalizeMu.TryLock() {
		return nil
	}
	defer b.finalizeMu.Unlock()
	var failures []error
	var fenceErr error
	checkFence := func(ctx context.Context) error {
		fenceErr = fence(ctx)
		return fenceErr
	}
	if err := b.fenceStaticLaunches(ctx, checkFence); err != nil {
		return err
	}
	for _, account := range slices.Sorted(maps.Keys(b.cfg.Pools)) {
		s := backend.Scope{Pool: b.cfg.Pools[account]}
		// Pool keys may be operator labels; those launches carry their account in the marker.
		if id, err := resource.Parse[resource.AccountID](account); err == nil {
			s.Account = id
		}
		if _, err := b.poolForMutation(ctx, s); err != nil {
			failures = append(failures, err)
			continue
		}
		vms, err := b.visibleVMs(ctx, s)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		inventory := launchInventory{vms: vms}
		for _, vm := range vms {
			if vm.Pool != s.Pool || vm.Status == "unknown" {
				continue
			}
			if err := b.finalizeLaunch(ctx, s, vm, &inventory, checkFence); err != nil {
				failures = append(failures, fmt.Errorf("proxmox: finalize VM %d: %w", vm.VMID, err))
			}
			if ctx.Err() != nil || fenceErr != nil {
				return errors.Join(failures...)
			}
		}
	}
	return errors.Join(failures...)
}

func (b *Backend) finalizeLaunch(
	ctx context.Context, s backend.Scope, vm inventoryVM, inventory *launchInventory, fence func(context.Context) error,
) error {
	target := pveclient.VM{Node: vm.Node, VMID: vm.VMID}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return err
	}
finalize:
	for stage := range 2 {
		for attempt := range 2 {
			if inventory.stale || stage == 1 || attempt > 0 {
				inventory.vms, err = b.visibleVMs(ctx, s)
				if err != nil {
					return err
				}
				inventory.stale = false
			}
			if !slices.ContainsFunc(inventory.vms, func(v inventoryVM) bool {
				return v.VMID == vm.VMID && v.Node == vm.Node && v.Pool == s.Pool && v.Status != "unknown"
			}) {
				return resource.Denied("proxmox: finalize VM left its pool or went offline")
			}
			cfg, err := b.client.VMConfig(ctx, target)
			if err != nil {
				return fmt.Errorf("read finalize config: %w", err)
			}
			marker, found, err := ReadLaunchMarker(cfg.Description)
			if err != nil {
				slog.WarnContext(ctx, "skipping undecodable launch marker", slog.Int("vmid", vm.VMID))
				break finalize
			}
			if !found || !s.Account.IsZero() && marker.Account != s.Account || cfg.Lock != "" || cfg.Template == 1 ||
				slices.Contains(strings.Split(cfg.Tags, ";"), "vws.holder") {
				return nil
			}
			s.Account = marker.Account
			reservation, err := ids.Reservation(marker.Key)
			if err != nil {
				return err
			}
			expected, err := LaunchMarkerTags(marker, reservation)
			if err != nil {
				return err
			}
			if b.cfg.LiveTests {
				user, err := descriptionTags(cfg.Description)
				if err != nil {
					return err
				}
				live, err := liveRunTag(user)
				if err != nil {
					return err
				}
				if live != "" {
					expected = append(expected, live)
				}
			}
			tags := strings.FieldsFunc(cfg.Tags, func(r rune) bool { return r == ';' })
			complete := true
			for _, tag := range expected {
				if !slices.Contains(tags, tag) {
					complete = false
					tags = append(tags, tag)
				}
			}
			if complete || slices.Contains(tags, LaunchFailureTag) {
				return nil
			}
			fields := url.Values{"tags": {strings.Join(tags, ";")}, "description": {cfg.Description}}
			if stage == 0 {
				fields, err = b.launchConfig(ctx, ids, marker, cfg)
				if err != nil {
					return err
				}
				if len(fields) == 0 {
					break
				}
			}
			if err := fence(ctx); err != nil {
				return err
			}
			err = b.client.WriteConfig(ctx, target, cfg.Digest, fields)
			if pveclient.DigestConflict(err) {
				if attempt == 0 {
					continue
				}
				return resource.Conflict(resource.KindInstance, "", "config changed during launch finalize")
			}
			if err != nil {
				return fmt.Errorf("write finalize config: %w", err)
			}
			break
		}
		if stage == 0 {
			inventory.vms, err = b.visibleVMs(ctx, s)
			if err != nil {
				return err
			}
			index := slices.IndexFunc(inventory.vms, func(v inventoryVM) bool {
				return v.VMID == vm.VMID && v.Node == vm.Node && v.Pool == s.Pool
			})
			if index < 0 {
				return resource.Denied("proxmox: finalize VM left its pool")
			}
			if inventory.vms[index].Status == "running" {
				continue
			}
			rows, err := b.client.OwnTasks(ctx, vm.Node, url.Values{
				"vmid": {strconv.Itoa(vm.VMID)}, "typefilter": {"qmstart"}, "limit": {"1000"},
			})
			if err != nil {
				return fmt.Errorf("read launch start tasks: %w", err)
			}
			var upid string
			if len(rows) > 0 && rows[0].Status == "RUNNING" {
				upid = rows[0].UPID
			} else {
				if err := fence(ctx); err != nil {
					return err
				}
				upid, err = b.client.Power(ctx, target, "start", 0)
			}
			if err == nil {
				inventory.stale = true
				err = b.client.WaitTask(ctx, pveclient.Task{Node: vm.Node, UPID: upid}, pveclient.StartWait)
			}
			if err != nil {
				return fmt.Errorf("start finalized VM: %w", err)
			}
		}
	}
	return nil
}

func (b *Backend) launchConfig(
	ctx context.Context, ids IDs, marker LaunchMarker, cfg pveclient.VMConfig,
) (url.Values, error) {
	typ, ok := ResolveInstanceType(marker.Type)
	if !ok {
		return nil, resource.Invalid("instanceType", "unknown launch instance type")
	}
	bridges, err := b.bridges(ctx)
	if err != nil {
		return nil, err
	}
	index := slices.IndexFunc(bridges, func(br bridge) bool { return br.Subnet == marker.Subnet })
	if index < 0 {
		return nil, resource.NotFound(resource.KindSubnet, marker.Subnet.String())
	}
	if cfg.Drives["scsi0"] == "" {
		return nil, resource.Conflict(resource.KindInstance, "", "launch root disk is missing")
	}
	serial, err := ids.RootVolumeSerial(marker.UUID)
	if err != nil {
		return nil, err
	}
	net := "virtio"
	if mac := option(cfg.Net0, "virtio"); mac != "" {
		net += "=" + mac
	}
	net += ",bridge=" + bridges[index].Iface + ",firewall=0"
	fields := url.Values{
		"smbios1": {launchOption(cfg.SMBIOS1, "uuid", marker.UUID)},
		"cores":   {strconv.Itoa(typ.VCPUs)}, "memory": {strconv.Itoa(typ.MemoryMiB)},
		"net0": {net}, "serial0": {"socket"}, "agent": {"1"},
		"scsi0": {launchOption(cfg.Drives["scsi0"], "serial", serial)},
	}
	r, err := b.staticSubnet(marker.Subnet)
	if err != nil {
		return nil, err
	}
	if r.prefix.IsValid() && (!privateIP(cfg.IPConfig0).IsValid() || configUUID(cfg) != marker.UUID) {
		used, _, err := b.scanStaticIPs(ctx, marker.Subnet)
		if err != nil {
			return nil, err
		}
		ip, err := r.free(used, 1)
		if err != nil {
			return nil, err
		}
		fields.Set("ipconfig0", fmt.Sprintf("ip=%s/%d,gw=%s", ip, r.prefix.Bits(), r.gw))
	}
	current := map[string]string{
		"smbios1": cfg.SMBIOS1, "cores": strconv.Itoa(cfg.Cores), "memory": strconv.Itoa(cfg.Memory),
		"net0": cfg.Net0, "serial0": cfg.Serial0, "agent": cfg.Agent, "scsi0": cfg.Drives["scsi0"],
	}
	for key, value := range current {
		if fields.Get(key) == value {
			delete(fields, key)
		}
	}
	return fields, nil
}

func launchOption(text, key, value string) string {
	parts := strings.FieldsFunc(text, func(r rune) bool { return r == ',' })
	for i, part := range parts {
		if strings.HasPrefix(part, key+"=") {
			parts[i] = key + "=" + value
			return strings.Join(parts, ",")
		}
	}
	return strings.Join(append(parts, key+"="+value), ",")
}
