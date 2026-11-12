package proxmox

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func volumeAccepted(
	scope backend.Scope, key string, action resource.Action, vol resource.Volume,
) (resource.Accepted[resource.Volume], error) {
	hash := sha256.Sum256([]byte(key))
	id, err := (syncOperation{
		action: action, kind: resource.KindVolume,
		local: strings.TrimPrefix(vol.ID.String(), "vol-"), keyHash: [8]byte(hash[:8]),
	}).encode()
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	now := time.Now()
	return resource.Accepted[resource.Volume]{Items: []resource.Volume{vol}, Operation: resource.Operation{
		ID: id, Action: action, State: resource.OperationSucceeded, OwnerID: scope.Account,
		Targets: []resource.Ref{vol.ID.Ref()}, CreateTime: now, UpdateTime: now,
	}}, nil
}

// CreateVolume recovers both allocated images and configured disks from PVE.
func (b *Backend) CreateVolume(
	ctx context.Context, m backend.Mutation, req resource.CreateVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	pool, err := b.poolForMutation(ctx, m.Scope)
	if b.cfg.ReadOnly {
		return resource.Accepted[resource.Volume]{}, resource.Unsupported("CreateVolume", "read-only")
	}
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	if !req.SnapshotID.IsZero() {
		return resource.Accepted[resource.Volume]{}, resource.Unsupported("CreateVolume", "no snapshot sources")
	}
	zone := req.Zone
	if zone == "" {
		zone = b.region + "a"
	}
	req.Zone = resource.ZoneName
	req, err = req.Normalize()
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	req.Zone = zone
	storage := b.cfg.Storages[string(req.Type)]
	if storage == "" {
		return resource.Accepted[resource.Volume]{}, resource.Unsupported("CreateVolume", "no storage for volume type")
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	serial, err := ids.VolumeSerial(m.Key, 0)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	id, _, err := ids.Volume(serial, "", "")
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	var tags []string
	for key, value := range req.Tags {
		tag, err := EncodeTag(key, value)
		if err != nil {
			return resource.Accepted[resource.Volume]{}, err
		}
		tag = "vws.vt." + serial[:8] + "." + strings.TrimPrefix(tag, userTagPrefix)
		if len(tag) > 128 {
			return resource.Accepted[resource.Volume]{}, resource.Unsupported("CreateVolume", "encoded tag exceeds 128 bytes")
		}
		tags = append(tags, tag)
	}
	slices.Sort(tags)
	b.volumeMu.Lock()
	defer b.volumeMu.Unlock()
	vm, err := b.volumeHolder(ctx, m.Scope, pool, zone)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	cfg, err := b.client.VMConfig(ctx, vm)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	vol := resource.Volume{
		ID: id, OwnerID: m.Account, SizeGiB: req.SizeGiB, Zone: zone,
		Type: req.Type, State: resource.VolumeAvailable, Format: "raw", IDSource: string(SourceSerial), Tags: req.Tags,
	}
	for _, drive := range cfg.Drives {
		if option(drive, "serial") != serial {
			continue
		}
		volid, _, _ := strings.Cut(drive, ",")
		rows, err := b.client.StorageContent(ctx, vm.Node, storage)
		if err != nil {
			return resource.Accepted[resource.Volume]{}, err
		}
		for _, row := range rows {
			if row.VolID == volid && row.Size == req.SizeGiB<<30 {
				return volumeAccepted(m.Scope, m.Key, resource.ActionCreateVolume, vol)
			}
		}
		return resource.Accepted[resource.Volume]{}, resource.IdempotencyMismatch()
	}
	slot := ""
	for i := range 22 {
		key := fmt.Sprintf("scsi%d", i)
		if cfg.Drives[key] == "" {
			slot = key
			break
		}
	}
	if slot == "" {
		return resource.Accepted[resource.Volume]{},
			resource.Conflict(resource.KindVolume, id.String(), "volume holder has no free disk slot")
	}
	number, _ := new(big.Int).SetString(serial, 16)
	filename := fmt.Sprintf("vm-%d-disk-%s.raw", vm.VMID, number.String())
	rows, err := b.client.StorageContent(ctx, vm.Node, storage)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	volid := ""
	for _, row := range rows {
		if row.VMID == vm.VMID && (strings.HasSuffix(row.VolID, ":"+filename) || strings.HasSuffix(row.VolID, "/"+filename)) {
			if row.Size != req.SizeGiB<<30 {
				return resource.Accepted[resource.Volume]{}, resource.IdempotencyMismatch()
			}
			volid = row.VolID
		}
	}
	if volid == "" {
		err = b.client.VolumeWrite(ctx, http.MethodPost, "/nodes/"+vm.Node+"/storage/"+storage+"/content",
			url.Values{
				"vmid": {strconv.Itoa(vm.VMID)}, "filename": {filename},
				"size": {fmt.Sprintf("%dG", req.SizeGiB)}, "format": {"raw"},
			}, &volid)
		if err != nil {
			return resource.Accepted[resource.Volume]{}, fmt.Errorf("proxmox: allocate volume: %w", err)
		}
	}
	currentTags := strings.Split(cfg.Tags, ";")
	currentTags = slices.DeleteFunc(currentTags, func(tag string) bool {
		return strings.HasPrefix(tag, "vws.vt."+serial[:8]+".")
	})
	tags = append(currentTags, tags...)
	err = b.client.VolumeWrite(ctx, http.MethodPut, volumeVMPath(vm)+"/config", url.Values{
		slot: {volid + ",serial=" + serial}, "digest": {cfg.Digest}, "tags": {strings.Join(tags, ";")},
	}, nil)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, fmt.Errorf("proxmox: configure volume: %w", err)
	}
	return volumeAccepted(m.Scope, m.Key, resource.ActionCreateVolume, vol)
}

// DeleteVolume only unlinks an unattached disk in the caller's pool.
func (b *Backend) DeleteVolume(
	ctx context.Context, m backend.Mutation, req resource.DeleteVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	vol, err := b.volumeForMutation(ctx, m.Scope, req.ID)
	if b.cfg.ReadOnly {
		return resource.Accepted[resource.Volume]{}, resource.Unsupported("DeleteVolume", "read-only")
	}
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	if vol.State == resource.VolumeInUse {
		return resource.Accepted[resource.Volume]{}, resource.VolumeAttached(req.ID)
	}
	b.volumeMu.Lock()
	defer b.volumeMu.Unlock()
	vm, cfg, key, err := b.volumeDrive(ctx, m.Scope, req.ID)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	prefix := "vws.vt." + strings.TrimPrefix(req.ID.String(), "vol-")[:8] + "."
	tags := slices.DeleteFunc(strings.Split(cfg.Tags, ";"), func(tag string) bool {
		return strings.HasPrefix(tag, prefix)
	})
	if err := b.client.VolumeWrite(ctx, http.MethodPut, volumeVMPath(vm)+"/config",
		url.Values{"tags": {strings.Join(tags, ";")}, "digest": {cfg.Digest}}, nil); err != nil {
		return resource.Accepted[resource.Volume]{}, fmt.Errorf("proxmox: remove deleted volume tags: %w", err)
	}
	if err := b.client.VolumeWrite(ctx, http.MethodPut, volumeVMPath(vm)+"/unlink",
		url.Values{"idlist": {key}, "force": {"1"}}, nil); err != nil {
		current, restoreErr := b.client.VMConfig(ctx, vm)
		if restoreErr == nil && current.Drives[key] == cfg.Drives[key] {
			restored := strings.Split(current.Tags, ";")
			for _, tag := range strings.Split(cfg.Tags, ";") {
				if strings.HasPrefix(tag, prefix) {
					restored = append(restored, tag)
				}
			}
			restoreErr = b.client.VolumeWrite(ctx, http.MethodPut, volumeVMPath(vm)+"/config",
				url.Values{"tags": {strings.Join(restored, ";")}, "digest": {current.Digest}}, nil)
		}
		return resource.Accepted[resource.Volume]{}, errors.Join(fmt.Errorf("proxmox: delete volume: %w", err), restoreErr)
	}
	vol.State = resource.VolumeDeleting
	return volumeAccepted(m.Scope, m.Key, resource.ActionDeleteVolume, vol)
}
