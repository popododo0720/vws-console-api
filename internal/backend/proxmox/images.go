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

// DescribeImages lists UUID-bearing templates in the caller's current pools.
func (b *Backend) DescribeImages(
	ctx context.Context, s backend.Scope, q resource.ImageQuery,
) (resource.Page[resource.Image], error) {
	q, err := q.Normalize()
	if err != nil {
		return resource.Page[resource.Image]{}, err
	}
	vms, err := b.poolInventory(ctx, s, true)
	if err != nil {
		return resource.Page[resource.Image]{}, err
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return resource.Page[resource.Image]{}, err
	}
	var items []resource.Image
	var readErr error
	for _, vm := range vms {
		if slices.Contains(strings.Split(vm.Tags, ";"), "vws.holder") {
			continue
		}
		cfg, err := b.client.VMConfig(ctx, pveclient.VM{Node: vm.Node, VMID: vm.VMID})
		if err != nil {
			if ctx.Err() != nil {
				return resource.Page[resource.Image]{}, fmt.Errorf("proxmox: read image config: %w", err)
			}
			readErr = err
			slog.WarnContext(ctx, "skipping unavailable image config", slog.Int("vmid", vm.VMID), slog.Any("error", err))
			continue
		}
		if cfg.Template != 1 || slices.Contains(strings.Split(cfg.Tags, ";"), "vws.holder") {
			continue
		}
		id, err := ids.Image(configUUID(cfg))
		if err != nil {
			slog.WarnContext(ctx, "skipping invalid template", slog.Int("vmid", vm.VMID), slog.Any("error", err))
			continue
		}
		if !q.Owner.IsZero() && q.Owner != s.Account || len(q.IDs) != 0 && !slices.Contains(q.IDs, id) {
			continue
		}
		items = append(items, resource.Image{
			ID: id, OwnerID: s.Account, Name: cfg.Name, State: "available",
			Description: cfg.Description, SizeGiB: imageRootSize(cfg),
		})
	}
	if len(q.IDs) == 1 && len(items) == 0 {
		if readErr != nil {
			return resource.Page[resource.Image]{}, powerUnavailable(readErr)
		}
		return resource.Page[resource.Image]{}, resource.ImageNotFound(q.IDs[0])
	}
	return networkPage(items, q.Page)
}

func imageRootSize(cfg pveclient.VMConfig) int64 {
	keys := strings.Split(option(cfg.Boot, "order"), ";")
	if keys[0] == "" {
		keys = []string{cfg.BootDisk}
	}
	for _, key := range keys {
		drive := cfg.Drives[key]
		if diskDevice(key) == "" || drive == "" || option(drive, "media") == "cdrom" ||
			strings.Contains(strings.SplitN(drive, ",", 2)[0], "cloudinit") {
			continue
		}
		return driveSizeGiB(drive)
	}
	return 0
}
