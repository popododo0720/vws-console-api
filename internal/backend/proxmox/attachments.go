package proxmox

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const detachDescriptionPrefix = "vws:detach "

type detachRecord struct {
	Key         string                    `json:"key"`
	Fingerprint string                    `json:"fingerprint"`
	At          int64                     `json:"at"`
	Item        resource.VolumeAttachment `json:"item"`
	Operation   resource.OperationID      `json:"operation"`
	Pending     bool                      `json:"pending"`
}

func attachmentSlot(device string) (string, error) {
	if len(device) != 8 || !strings.HasPrefix(device, "/dev/sd") || device[7] < 'f' || device[7] > 'z' {
		return "", resource.Invalid("device", "Proxmox data devices must be /dev/sdf through /dev/sdz")
	}
	return "scsi" + strconv.Itoa(int(device[7]-'f')+1), nil
}

func detachRecords(description string) ([]detachRecord, string, error) {
	var records []detachRecord
	var kept []string
	found := false
	for line := range strings.SplitSeq(description, "\n") {
		body, match := strings.CutPrefix(strings.TrimSuffix(line, "\r"), detachDescriptionPrefix)
		if !match {
			kept = append(kept, line)
			continue
		}
		if found || len(description) > 8192 {
			return nil, "", resource.Conflict(resource.KindInstance, "", "ambiguous detach records")
		}
		found = true
		if err := json.Unmarshal([]byte(body), &records); err != nil {
			return nil, "", fmt.Errorf("proxmox: read detach records: %w", err)
		}
		if len(records) > backend.MaxDetachReplays {
			return nil, "", resource.Conflict(resource.KindInstance, "", "too many detach records")
		}
		for _, rec := range records {
			if rec.Key == "" || rec.Fingerprint == "" || rec.Item.VolumeID.IsZero() ||
				rec.Item.InstanceID.IsZero() || rec.Operation.IsZero() || rec.At <= 0 {
				return nil, "", resource.Conflict(resource.KindInstance, "", "invalid detach record")
			}
		}
	}
	return records, strings.TrimRight(strings.Join(kept, "\n"), "\n"), nil
}

func (b *Backend) saveDetaches(
	ctx context.Context, vm pveclient.VM, cfg pveclient.VMConfig, records []detachRecord,
) error {
	_, text, err := detachRecords(cfg.Description)
	if err != nil {
		return err
	}
	body, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("proxmox: encode detach records: %w", err)
	}
	description := text
	if len(records) != 0 {
		if description != "" {
			description += "\n"
		}
		description += detachDescriptionPrefix + string(body)
	}
	if len(description) > 8192 {
		return resource.TagLimitExceeded("description", "detach records exceed the 8192-byte VM description limit")
	}
	tags := slices.DeleteFunc(strings.Split(cfg.Tags, ";"), func(tag string) bool {
		return strings.HasPrefix(tag, "vws.d.")
	})
	for _, rec := range records {
		fp := sha256.Sum256([]byte(rec.Fingerprint))
		tags = append(tags, fmt.Sprintf("vws.d.%s.%x.%x", rec.Key, fp[:4], rec.At))
	}
	if err := b.client.WriteConfigTags(ctx, vm, cfg.Digest, strings.Join(tags, ";"), description); err != nil {
		return fmt.Errorf("proxmox: save detach result: %w", err)
	}
	return nil
}

// AttachVolume reassigns a holder disk without changing its serial.
func (b *Backend) AttachVolume(
	ctx context.Context, m backend.Mutation, req resource.AttachVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	vol, err := b.volumeForMutation(ctx, m.Scope, req.VolumeID)
	if b.cfg.ReadOnly {
		return resource.Accepted[resource.Volume]{}, resource.Unsupported("AttachVolume", "read-only")
	}
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	slot, err := attachmentSlot(req.Device)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	row, err := b.vmForMutation(ctx, m.Scope, req.InstanceID)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	b.volumeMu.Lock()
	defer b.volumeMu.Unlock()
	vol, err = b.volumeForMutation(ctx, m.Scope, req.VolumeID)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	if vol.State != resource.VolumeAvailable && (vol.InstanceID != req.InstanceID || vol.Device != req.Device) {
		return resource.Accepted[resource.Volume]{}, resource.VolumeNotAvailable(vol.ID)
	}
	pool, err := b.poolForMutation(ctx, m.Scope)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	holder, err := b.volumeHolder(ctx, m.Scope, pool, vol.Zone)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	target := pveclient.VM{Node: row.Node, VMID: row.VMID}
	key := ""
	if vol.State == resource.VolumeAvailable {
		_, _, key, err = b.volumeDrive(ctx, m.Scope, vol.ID)
		if err != nil {
			return resource.Accepted[resource.Volume]{}, err
		}
	}
	if err := b.moveVolume(ctx, holder, target, key, slot, vol.ID); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	vol, err = b.volumeForMutation(ctx, m.Scope, req.VolumeID)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	return volumeAccepted(m.Scope, m.Key, resource.ActionAttachVolume, vol)
}

// DetachVolume keeps a bounded durable result on the original instance.
func (b *Backend) DetachVolume(
	ctx context.Context, m backend.Mutation, req resource.DetachVolumeRequest,
) (resource.Accepted[resource.VolumeAttachment], error) {
	vol, err := b.volumeForMutation(ctx, m.Scope, req.VolumeID)
	var zero resource.Accepted[resource.VolumeAttachment]
	if b.cfg.ReadOnly {
		return zero, resource.Unsupported("DetachVolume", "read-only")
	}
	if err != nil {
		return zero, err
	}
	b.volumeMu.Lock()
	defer b.volumeMu.Unlock()
	vol, err = b.volumeForMutation(ctx, m.Scope, req.VolumeID)
	if err != nil {
		return zero, err
	}
	key := sha256.Sum256([]byte(m.Key))
	key16 := fmt.Sprintf("%x", key[:8])
	now := time.Now()
	if !m.MintedToken {
		rows, err := b.poolVMs(ctx, m.Scope)
		if err != nil {
			return zero, err
		}
		for _, row := range rows {
			if !strings.Contains(";"+row.Tags, ";vws.d."+key16+".") {
				continue
			}
			vm := pveclient.VM{Node: row.Node, VMID: row.VMID}
			cfg, err := b.client.VMConfig(ctx, vm)
			if err != nil {
				return zero, fmt.Errorf("proxmox: find detach replay: %w", err)
			}
			records, _, err := detachRecords(cfg.Description)
			if err != nil {
				return zero, (&resource.Error{
					Code: resource.CodeUnavailable, Message: "detach replay record is unreadable",
				}).WithCause(err)
			}
			for i, rec := range records {
				if rec.Key != key16 || detachRecordExpired(rec, now) {
					continue
				}
				if rec.Fingerprint != m.Fingerprint || rec.Item.VolumeID != req.VolumeID ||
					!req.InstanceID.IsZero() && req.InstanceID != rec.Item.InstanceID ||
					req.Device != "" && req.Device != rec.Item.Device {
					return zero, resource.IdempotencyMismatch()
				}
				if rec.Pending {
					return b.finishDetach(ctx, m.Scope, vm, records, i)
				}
				return detachAccepted(m.Scope, rec), nil
			}
		}
	}
	if vol.State != resource.VolumeInUse {
		return zero, resource.VolumeNotInUse(vol.ID)
	}
	if !req.InstanceID.IsZero() && req.InstanceID != vol.InstanceID || req.Device != "" && req.Device != vol.Device {
		return zero, resource.AttachmentNotFound(vol.ID)
	}
	if vol.Device == "/dev/sda" {
		return zero, resource.VolumeRootDevice(vol.ID)
	}
	if _, err := attachmentSlot(vol.Device); err != nil {
		return zero, err
	}
	row, err := b.vmForMutation(ctx, m.Scope, vol.InstanceID)
	if err != nil {
		return zero, err
	}
	if row.Status != "stopped" {
		return zero, resource.Conflict(resource.KindVolume, vol.ID.String(), "detach requires a stopped instance")
	}
	vm := pveclient.VM{Node: row.Node, VMID: row.VMID}
	cfg, err := b.client.VMConfig(ctx, vm)
	if err != nil {
		return zero, fmt.Errorf("proxmox: read detach instance: %w", err)
	}
	records, _, err := detachRecords(cfg.Description)
	if err != nil {
		return zero, err
	}
	records = slices.DeleteFunc(records, func(rec detachRecord) bool {
		return detachRecordExpired(rec, now)
	})
	for _, rec := range records {
		if rec.Pending && rec.Item.VolumeID == vol.ID {
			return zero, resource.Conflict(resource.KindVolume, vol.ID.String(), "an earlier detach must finish first")
		}
	}
	opID, err := (syncOperation{
		action: resource.ActionDetachVolume, kind: resource.KindInstance,
		local: strings.TrimPrefix(vol.InstanceID.String(), "i-"), keyHash: [8]byte(key[:8]),
	}).encode()
	if err != nil {
		return zero, err
	}
	rec := detachRecord{
		Key: key16, Fingerprint: m.Fingerprint, At: now.Unix(), Pending: true,
		Operation: opID, Item: resource.VolumeAttachment{
			VolumeID: vol.ID, OwnerID: m.Account, InstanceID: vol.InstanceID, Device: vol.Device,
			Status: resource.AttachmentDetaching, AttachTime: vol.AttachTime,
		},
	}
	if !m.MintedToken {
		if len(records) >= backend.MaxDetachReplays {
			return zero, backend.DetachReplaysExhausted(vol.InstanceID)
		}
		records = append(records, rec)
		if err := b.saveDetaches(ctx, vm, cfg, records); err != nil {
			return zero, err
		}
		return b.finishDetach(ctx, m.Scope, vm, records, len(records)-1)
	}
	if err := b.detachDisk(ctx, m.Scope, vm, rec); err != nil {
		return zero, err
	}
	return detachAccepted(m.Scope, rec), nil
}

func detachRecordExpired(rec detachRecord, now time.Time) bool {
	return backend.ClientTokenExpired(time.Unix(rec.At, 0), now)
}

func detachAccepted(scope backend.Scope, rec detachRecord) resource.Accepted[resource.VolumeAttachment] {
	return resource.Accepted[resource.VolumeAttachment]{
		Items: []resource.VolumeAttachment{rec.Item},
		Operation: resource.Operation{
			ID: rec.Operation, Action: resource.ActionDetachVolume,
			OwnerID: scope.Account, State: resource.OperationSucceeded, Targets: []resource.Ref{rec.Item.InstanceID.Ref()},
		},
	}
}

func (b *Backend) finishDetach(
	ctx context.Context, scope backend.Scope, vm pveclient.VM, records []detachRecord, index int,
) (resource.Accepted[resource.VolumeAttachment], error) {
	if err := b.detachDisk(ctx, scope, vm, records[index]); err != nil {
		return resource.Accepted[resource.VolumeAttachment]{}, err
	}
	cfg, err := b.client.VMConfig(ctx, vm)
	if err != nil {
		return resource.Accepted[resource.VolumeAttachment]{}, fmt.Errorf("proxmox: finalize detach: %w", err)
	}
	records[index].Pending = false
	if err := b.saveDetaches(ctx, vm, cfg, records); err != nil {
		return resource.Accepted[resource.VolumeAttachment]{}, err
	}
	return detachAccepted(scope, records[index]), nil
}

func (b *Backend) detachDisk(ctx context.Context, scope backend.Scope, vm pveclient.VM, rec detachRecord) error {
	row, err := b.vmForMutation(ctx, scope, rec.Item.InstanceID)
	if err != nil {
		return err
	}
	if row.Status != "stopped" {
		return resource.Conflict(resource.KindVolume, rec.Item.VolumeID.String(), "detach requires a stopped instance")
	}
	pool, err := b.poolForMutation(ctx, scope)
	if err != nil {
		return err
	}
	holder, err := b.volumeHolder(ctx, scope, pool, b.region+b.nodeLetter(ctx, vm.Node))
	if err != nil {
		return err
	}
	cfg, err := b.client.VMConfig(ctx, holder)
	if err != nil {
		return fmt.Errorf("proxmox: read detach holder: %w", err)
	}
	serial := strings.TrimPrefix(rec.Item.VolumeID.String(), "vol-")
	slot := ""
	for key, drive := range cfg.Drives {
		if option(drive, "serial") == serial {
			slot = key
		}
	}
	if slot == "" {
		for i := range 22 {
			if key := fmt.Sprintf("scsi%d", i); cfg.Drives[key] == "" {
				slot = key
				break
			}
		}
	}
	if slot == "" {
		return resource.Conflict(resource.KindVolume, rec.Item.VolumeID.String(), "volume holder has no free disk slot")
	}
	source, err := attachmentSlot(rec.Item.Device)
	if err != nil {
		return err
	}
	return b.moveVolume(ctx, vm, holder, source, slot, rec.Item.VolumeID)
}

func (b *Backend) moveVolume(
	ctx context.Context, source, target pveclient.VM, key, slot string, id resource.VolumeID,
) error {
	if source.Node != target.Node {
		return resource.Conflict(resource.KindVolume, id.String(), "volume and instance must be on the same node")
	}
	src, err := b.client.VMConfig(ctx, source)
	if err != nil {
		return fmt.Errorf("proxmox: read move source: %w", err)
	}
	dst, err := b.client.VMConfig(ctx, target)
	if err != nil {
		return fmt.Errorf("proxmox: read move target: %w", err)
	}
	records, _, err := detachRecords(dst.Description)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, rec := range records {
		if rec.Pending && rec.Item.VolumeID == id && !detachRecordExpired(rec, now) {
			return resource.Conflict(resource.KindVolume, id.String(), "an earlier detach must finish first")
		}
	}
	serial := strings.TrimPrefix(id.String(), "vol-")
	prefix := "vws.vt." + serial[:8] + "."
	if option(dst.Drives[slot], "serial") != serial {
		if src.Lock != "" || dst.Lock != "" || src.Protection == 1 {
			return resource.Conflict(resource.KindVolume, id.String(), "disk move is locked or protected")
		}
		if dst.Drives[slot] != "" {
			return resource.Conflict(resource.KindVolume, id.String(), "device is already occupied")
		}
		if option(src.Drives[key], "serial") != serial {
			return resource.NotFound(resource.KindVolume, id.String())
		}
		tags := slices.DeleteFunc(strings.Split(dst.Tags, ";"), func(tag string) bool {
			return strings.HasPrefix(tag, prefix)
		})
		for _, tag := range strings.Split(src.Tags, ";") {
			if strings.HasPrefix(tag, prefix) && !slices.Contains(tags, tag) {
				tags = append(tags, tag)
			}
		}
		if err := b.client.WriteConfigTags(ctx, target, dst.Digest, strings.Join(tags, ";"), dst.Description); err != nil {
			return fmt.Errorf("proxmox: copy volume tags: %w", err)
		}
		dst, err = b.client.VMConfig(ctx, target)
		if err != nil {
			return fmt.Errorf("proxmox: read move digest: %w", err)
		}
		var upid string
		if err := b.client.VolumeWrite(ctx, http.MethodPost, volumeVMPath(source)+"/move_disk", url.Values{
			"disk": {key}, "target-vmid": {strconv.Itoa(target.VMID)}, "target-disk": {slot},
			"delete": {"1"}, "digest": {src.Digest}, "target-digest": {dst.Digest},
		}, &upid); err != nil {
			return fmt.Errorf("proxmox: reassign volume: %w", err)
		}
		if err := b.client.WaitTask(ctx, pveclient.Task{Node: source.Node, UPID: upid}, pveclient.CloneWait); err != nil {
			return fmt.Errorf("proxmox: await volume reassignment: %w", err)
		}
		src, err = b.client.VMConfig(ctx, source)
		if err != nil {
			return fmt.Errorf("proxmox: read moved source: %w", err)
		}
	}
	tags := slices.DeleteFunc(strings.Split(src.Tags, ";"), func(tag string) bool {
		return strings.HasPrefix(tag, prefix) || tag == "vws.dot."+serial[:8]
	})
	if strings.Join(tags, ";") != src.Tags {
		if err := b.client.WriteConfigTags(ctx, source, src.Digest, strings.Join(tags, ";"), src.Description); err != nil {
			return fmt.Errorf("proxmox: remove moved volume tags: %w", err)
		}
	}
	return nil
}
