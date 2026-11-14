package proxmox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func driveSizeGiB(drive string) int64 {
	size := option(drive, "size")
	unit := float64(1) / (1 << 30)
	for i, suffix := range []string{"K", "M", "G", "T", "P"} {
		if strings.HasSuffix(size, suffix) {
			size = strings.TrimSuffix(size, suffix)
			unit = math.Pow(1024, float64(i-2))
			break
		}
	}
	n, err := strconv.ParseFloat(size, 64)
	gib := math.Ceil(n * unit)
	if err == nil && gib > 0 && gib < math.Exp2(63) {
		return int64(gib)
	}
	return 0
}

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
				if ctx.Err() != nil {
					return nil, fmt.Errorf("proxmox: read disk storage content: %w", err)
				}
				slog.WarnContext(ctx, "unavailable storage metadata",
					slog.String("node", vm.Node), slog.String("storage", storage), slog.Any("error", err))
			}
			content[cacheKey] = rows
		}
		index := slices.IndexFunc(rows, func(row pveclient.StorageContent) bool {
			return row.VolID == volid && row.Content == "images"
		})
		size := driveSizeGiB(drive)
		var format string
		if index >= 0 {
			format = rows[index].Format
			if size == 0 && rows[index].Size > 0 {
				size = (rows[index].Size-1)/(1<<30) + 1
			}
		}
		if size == 0 {
			slog.WarnContext(ctx, "disk size unavailable", slog.Int("vmid", vm.VMID), slog.String("drive", key))
		}
		vol := resource.Volume{
			ID: id, OwnerID: s.Account, State: resource.VolumeAvailable,
			SizeGiB: size, Format: format, IDSource: string(source),
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
