package proxmox

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (b *Backend) vmForMutation(
	ctx context.Context, s backend.Scope, id resource.InstanceID,
) (inventoryVM, error) {
	vms, err := b.poolVMs(ctx, s)
	if err != nil {
		return inventoryVM{}, err
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return inventoryVM{}, err
	}
	for _, vm := range vms {
		cfg, err := b.client.VMConfig(ctx, pveclient.VM{Node: vm.Node, VMID: vm.VMID})
		if err != nil {
			return inventoryVM{}, fmt.Errorf("proxmox: check mutation VM config: %w", err)
		}
		if cfg.Template == 1 || slices.Contains(strings.Split(cfg.Tags, ";"), "vws.holder") {
			continue
		}
		found, _, err := ids.Instance(VM{UUID: configUUID(cfg), VMID: vm.VMID, Ctime: option(cfg.Meta, "ctime")})
		if err != nil {
			return inventoryVM{}, err
		}
		if found == id {
			return vm, nil
		}
	}
	return inventoryVM{}, resource.NotFound(resource.KindInstance, id.String())
}

func (b *Backend) volumeForMutation(
	ctx context.Context, s backend.Scope, id resource.VolumeID,
) (resource.Volume, error) {
	page, err := b.DescribeVolumes(ctx, s, resource.VolumeQuery{IDs: []resource.VolumeID{id}})
	if err != nil {
		return resource.Volume{}, err
	}
	volume := page.Items[0]
	if !volume.InstanceID.IsZero() {
		if _, err := b.vmForMutation(ctx, s, volume.InstanceID); err != nil {
			if resource.CodeOf(err) == resource.CodeNotFound {
				return resource.Volume{}, resource.NotFound(resource.KindVolume, id.String())
			}
			return resource.Volume{}, err
		}
	}
	return volume, nil
}

func (b *Backend) snapshotForMutation(
	ctx context.Context, s backend.Scope, id resource.SnapshotID,
) (resource.Snapshot, error) {
	page, err := b.DescribeSnapshots(ctx, s, resource.SnapshotQuery{IDs: []resource.SnapshotID{id}})
	if err != nil {
		return resource.Snapshot{}, err
	}
	return page.Items[0], nil
}

func (b *Backend) poolForMutation(ctx context.Context, s backend.Scope) (string, error) {
	pool, mapped := b.cfg.Pools[s.Account.String()]
	if !mapped {
		pool = s.Account.String()
	}
	exists, err := b.PoolExists(ctx, pool)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", resource.Denied("proxmox: mutation requires an existing managed pool")
	}
	return pool, nil
}
