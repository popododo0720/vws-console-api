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

func diskDevice(key string) string {
	for _, bus := range []string{"scsi", "virtio", "sata", "ide"} {
		suffix, ok := strings.CutPrefix(key, bus)
		index, err := strconv.Atoi(suffix)
		if !ok || err != nil || index < 0 || index > 25 || suffix != strconv.Itoa(index) {
			continue
		}
		if bus == "scsi" && index > 0 {
			if index > 21 {
				return ""
			}
			index += 4
		}
		prefix := "/dev/sd"
		switch bus {
		case "virtio":
			prefix = "/dev/vd"
		case "ide":
			prefix = "/dev/hd"
		}
		return prefix + string(rune('a'+index))
	}
	return ""
}

func (b *Backend) vmVolumes(
	ctx context.Context, s backend.Scope, ids IDs, vm inventoryVM, cfg pveclient.VMConfig,
	content map[string][]pveclient.StorageContent,
) ([]resource.Volume, error) {
	holder := slices.Contains(strings.Split(cfg.Tags, ";"), "vws.holder")
	var instance resource.InstanceID
	var err error
	if !holder {
		instance, _, err = ids.Instance(VM{UUID: configUUID(cfg), VMID: vm.VMID, Ctime: option(cfg.Meta, "ctime")})
		if err != nil {
			return nil, err
		}
	}
	var out []resource.Volume
	for _, key := range slices.Sorted(maps.Keys(cfg.Drives)) {
		drive := cfg.Drives[key]
		device := diskDevice(key)
		volid := strings.SplitN(drive, ",", 2)[0]
		storage, volname, ok := strings.Cut(volid, ":")
		if !ok || device == "" || option(drive, "media") == "cdrom" || strings.Contains(volname, "cloudinit") {
			continue
		}
		serial, err := url.QueryUnescape(option(drive, "serial"))
		if err != nil {
			slog.WarnContext(ctx, "skipping invalid disk serial", slog.Int("vmid", vm.VMID), slog.String("drive", key))
			continue
		}
		id, source, err := ids.Volume(serial, storage, volname)
		if err != nil {
			slog.WarnContext(ctx, "skipping invalid disk", slog.Int("vmid", vm.VMID), slog.Any("error", err))
			continue
		}
		cacheKey := vm.Node + "/" + storage
		rows, cached := content[cacheKey]
		if !cached {
			rows, err = b.client.StorageContent(ctx, vm.Node, storage)
			if err != nil {
				return nil, fmt.Errorf("proxmox: read disk storage content: %w", err)
			}
			content[cacheKey] = rows
		}
		index := slices.IndexFunc(rows, func(row pveclient.StorageContent) bool {
			return row.VolID == volid && row.Content == "images" && row.Size > 0
		})
		if index < 0 {
			slog.WarnContext(ctx, "disk missing storage content", slog.Int("vmid", vm.VMID), slog.String("drive", key))
			continue
		}
		row := rows[index]
		vol := resource.Volume{
			ID: id, OwnerID: s.Account, State: resource.VolumeAvailable,
			SizeGiB: (row.Size-1)/(1<<30) + 1, Format: row.Format, IDSource: string(source),
			Zone: b.region + b.nodeLetter(ctx, vm.Node), Type: resource.VolumeStandard,
		}
		for name, mapped := range b.cfg.Storages {
			if mapped == storage {
				kind := resource.VolumeType(name)
				if kind.Valid() && (vol.Type == resource.VolumeStandard || kind < vol.Type) {
					vol.Type = kind
				}
			}
		}
		var encoded []string
		suffix := strings.TrimPrefix(id.String(), "vol-")[:8]
		for _, tag := range strings.Split(cfg.Tags, ";") {
			if rest, ok := strings.CutPrefix(tag, "vws.vt."+suffix+"."); ok {
				encoded = append(encoded, userTagPrefix+rest)
			}
		}
		tags, err := ReadTags(encoded, "")
		if err != nil {
			err = fmt.Errorf("%w: volume tags: %w", ErrInput, err)
		} else if len(tags.Other) != 0 {
			err = fmt.Errorf("%w: undecodable volume tag", ErrInput)
		}
		if err != nil {
			slog.WarnContext(ctx, "skipping volume with undecodable tags",
				slog.Int("vmid", vm.VMID), slog.String("drive", key), slog.Any("error", err))
			continue
		}
		vol.Tags = tags.User
		if !holder {
			vol.State, vol.InstanceID, vol.Device = resource.VolumeInUse, instance, device
			vol.AttachState = resource.AttachmentAttached
			vol.DeleteOnTermination = key == "scsi0" ||
				slices.Contains(strings.Split(cfg.Tags, ";"), "vws.dot."+suffix)
		}
		if source != SourceSerial {
			slog.WarnContext(ctx, "fallback ID", slog.Int("vmid", vm.VMID), slog.String("id_source", string(source)))
		}
		out = append(out, vol)
	}
	return out, nil
}

// DescribeVolumes includes holder disks while retaining pool ownership.
func (b *Backend) DescribeVolumes(
	ctx context.Context, s backend.Scope, q resource.VolumeQuery,
) (resource.Page[resource.Volume], error) {
	if _, err := q.Normalize(); err != nil {
		return resource.Page[resource.Volume]{}, err
	}
	vms, err := b.poolVMs(ctx, s)
	if err != nil {
		return resource.Page[resource.Volume]{}, err
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return resource.Page[resource.Volume]{}, err
	}
	content := map[string][]pveclient.StorageContent{}
	var out []resource.Volume
	for _, vm := range vms {
		cfg, err := b.client.VMConfig(ctx, pveclient.VM{Node: vm.Node, VMID: vm.VMID})
		if err != nil {
			if ctx.Err() != nil {
				return resource.Page[resource.Volume]{}, fmt.Errorf("proxmox: read volume VM config: %w", err)
			}
			slog.WarnContext(ctx, "skipping invalid volume VM config", slog.Int("vmid", vm.VMID), slog.Any("error", err))
			continue
		}
		if cfg.Template == 1 {
			continue
		}
		volumes, err := b.vmVolumes(ctx, s, ids, vm, cfg, content)
		if err != nil {
			if errors.Is(err, ErrInput) {
				slog.WarnContext(ctx, "skipping invalid volume VM", slog.Int("vmid", vm.VMID), slog.Any("error", err))
				continue
			}
			return resource.Page[resource.Volume]{}, err
		}
		for _, vol := range volumes {
			if len(q.IDs) == 0 || slices.Contains(q.IDs, vol.ID) {
				out = append(out, vol)
			}
		}
	}
	for _, id := range q.IDs {
		if !slices.ContainsFunc(out, func(vol resource.Volume) bool { return vol.ID == id }) {
			return resource.Page[resource.Volume]{}, resource.NotFound(resource.KindVolume, id.String())
		}
	}
	return networkPage(out, q.Page)
}
