package proxmox

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const holderDescription = "VWS volume holder - do not start"

func volumeVMPath(vm pveclient.VM) string {
	return "/nodes/" + vm.Node + "/qemu/" + strconv.Itoa(vm.VMID)
}

func (b *Backend) volumeHolder(ctx context.Context, scope backend.Scope, pool, zone string) (pveclient.VM, error) {
	vms, err := b.poolVMs(ctx, scope)
	if err != nil {
		return pveclient.VM{}, err
	}
	for _, row := range vms {
		vm := pveclient.VM{Node: row.Node, VMID: row.VMID}
		cfg, err := b.client.VMConfig(ctx, vm)
		if err != nil {
			return pveclient.VM{}, fmt.Errorf("proxmox: locate volume holder: %w", err)
		}
		if !slices.Contains(strings.Split(cfg.Tags, ";"), "vws.holder") {
			continue
		}
		if cfg.Template != 0 || row.Status != "stopped" || cfg.Lock != "" {
			return pveclient.VM{}, resource.Conflict(resource.KindVolume, "", "volume holder is not ready")
		}
		if b.region+b.nodeLetter(ctx, row.Node) != zone {
			return pveclient.VM{}, resource.Invalid("availabilityZone", "pool volume holder is in another zone")
		}
		return vm, nil
	}
	nodes, err := b.client.Nodes(ctx)
	if err != nil {
		return pveclient.VM{}, err
	}
	slices.SortFunc(nodes, func(a, c pveclient.Node) int { return strings.Compare(a.Node, c.Node) })
	for _, node := range nodes {
		if node.Status != "online" || b.region+b.nodeLetter(ctx, node.Node) != zone {
			continue
		}
		id, err := b.client.NextVolumeVMID(ctx)
		if err != nil {
			return pveclient.VM{}, err
		}
		vm := pveclient.VM{Node: node.Node, VMID: id}
		var upid string
		err = b.client.VolumeWrite(ctx, http.MethodPost, "/nodes/"+node.Node+"/qemu", url.Values{
			"vmid": {strconv.Itoa(id)}, "pool": {pool}, "name": {"vws-holder-" + pool},
			"tags": {"vws.holder"}, "description": {holderDescription}, "start": {"0"},
		}, &upid)
		if err != nil {
			return pveclient.VM{}, fmt.Errorf("proxmox: create volume holder: %w", err)
		}
		if err := b.client.WaitTask(ctx, pveclient.Task{Node: node.Node, UPID: upid}, pveclient.StartWait); err != nil {
			return pveclient.VM{}, fmt.Errorf("proxmox: await volume holder: %w", err)
		}
		return vm, nil
	}
	return pveclient.VM{}, resource.Invalid("availabilityZone", "no online node in requested zone")
}

func (b *Backend) volumeDrive(
	ctx context.Context, scope backend.Scope, id resource.VolumeID,
) (pveclient.VM, pveclient.VMConfig, string, error) {
	rows, err := b.poolVMs(ctx, scope)
	if err != nil {
		return pveclient.VM{}, pveclient.VMConfig{}, "", err
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return pveclient.VM{}, pveclient.VMConfig{}, "", err
	}
	for _, row := range rows {
		vm := pveclient.VM{Node: row.Node, VMID: row.VMID}
		cfg, err := b.client.VMConfig(ctx, vm)
		if err != nil {
			return vm, cfg, "", err
		}
		if cfg.Template != 0 {
			continue
		}
		for key, drive := range cfg.Drives {
			volid, _, _ := strings.Cut(drive, ",")
			storage, name, _ := strings.Cut(volid, ":")
			serial, err := url.QueryUnescape(option(drive, "serial"))
			if err != nil {
				continue
			}
			found, _, err := ids.Volume(serial, storage, name)
			if err == nil && found == id {
				return vm, cfg, key, nil
			}
		}
	}
	return pveclient.VM{}, pveclient.VMConfig{}, "", resource.NotFound(resource.KindVolume, id.String())
}
