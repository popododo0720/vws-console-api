package proxmox

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// DescribeSnapshots exposes disk-only VM snapshots within the caller's pool.
func (b *Backend) DescribeSnapshots(
	ctx context.Context, s backend.Scope, q resource.SnapshotQuery,
) (resource.Page[resource.Snapshot], error) {
	if _, err := q.Normalize(); err != nil {
		return resource.Page[resource.Snapshot]{}, err
	}
	vms, err := b.poolVMs(ctx, s)
	if err != nil {
		return resource.Page[resource.Snapshot]{}, err
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return resource.Page[resource.Snapshot]{}, err
	}
	content := map[string][]pveclient.StorageContent{}
	var out []resource.Snapshot
	for _, vm := range vms {
		target := pveclient.VM{Node: vm.Node, VMID: vm.VMID}
		cfg, err := b.client.VMConfig(ctx, target)
		if err != nil {
			if ctx.Err() != nil {
				return resource.Page[resource.Snapshot]{}, fmt.Errorf("proxmox: read snapshot VM config: %w", err)
			}
			slog.WarnContext(ctx, "skipping invalid snapshot VM config", slog.Int("vmid", vm.VMID), slog.Any("error", err))
			continue
		}
		if cfg.Template == 1 {
			continue
		}
		rows, err := b.client.Snapshots(ctx, target)
		if err != nil {
			return resource.Page[resource.Snapshot]{}, fmt.Errorf("proxmox: list VM snapshots: %w", err)
		}
		var volumes []resource.Volume
		for _, row := range rows {
			if row.Name == "current" || row.VMState != 0 {
				continue
			}
			id, err := ids.Snapshot(configUUID(cfg), row.Name)
			if err != nil {
				slog.WarnContext(ctx, "skipping invalid snapshot", slog.Int("vmid", vm.VMID), slog.Any("error", err))
				continue
			}
			tags, err := ReadTags(nil, row.Description)
			if err != nil {
				slog.WarnContext(ctx, "skipping invalid snapshot tags", slog.Int("vmid", vm.VMID), slog.Any("error", err))
				continue
			}
			if volumes == nil {
				volumes, err = b.vmVolumes(ctx, s, ids, vm, cfg, content)
				if err != nil {
					if ctx.Err() != nil {
						return resource.Page[resource.Snapshot]{}, err
					}
					slog.WarnContext(ctx, "skipping VM with unreadable volumes",
						slog.Int("vmid", vm.VMID), slog.Any("error", err))
					break
				}
			}
			if len(volumes) == 0 {
				continue
			}
			// A VM snapshot has one ID; without a requested volume, expose its first disk.
			vol := volumes[0]
			first, _, _ := strings.Cut(row.Description, "\n")
			if _, local, ok := strings.Cut(first, " vws:vol="); ok && strings.HasPrefix(first, "vws:fp=") {
				for _, candidate := range volumes {
					if candidate.ID.String() == "vol-"+local {
						vol = candidate
						break
					}
				}
			}
			if len(q.IDs) == 0 || slices.Contains(q.IDs, id) {
				out = append(out, resource.Snapshot{
					ID: id, OwnerID: s.Account, VolumeID: vol.ID, VolumeSize: vol.SizeGiB,
					State: resource.SnapshotCompleted, Description: row.Description, Tags: tags.User,
				})
			}
		}
	}
	for _, id := range q.IDs {
		if !slices.ContainsFunc(out, func(snap resource.Snapshot) bool { return snap.ID == id }) {
			return resource.Page[resource.Snapshot]{}, resource.NotFound(resource.KindSnapshot, id.String())
		}
	}
	return networkPage(out, q.Page)
}
