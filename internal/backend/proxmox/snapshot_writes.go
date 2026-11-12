package proxmox

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// CreateSnapshot snapshots every disk on the volume's owning VM.
func (b *Backend) CreateSnapshot(
	ctx context.Context, m backend.Mutation, req resource.CreateSnapshotRequest,
) (resource.Accepted[resource.Snapshot], error) {
	vol, err := b.volumeForMutation(ctx, m.Scope, req.VolumeID)
	if b.cfg.ReadOnly {
		return resource.Accepted[resource.Snapshot]{}, resource.Unsupported("CreateSnapshot", "read-only")
	}
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	if _, err := req.Normalize(); err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	if m.Key == "" || len(m.Fingerprint) < 16 || strings.Trim(m.Fingerprint, "0123456789abcdef") != "" {
		return resource.Accepted[resource.Snapshot]{}, resource.Invalid("mutation", "key and hex fingerprint required")
	}
	sum := sha256.Sum256([]byte(m.Key))
	name := fmt.Sprintf("vws-%x", sum[:8])
	marker := "vws:fp=" + m.Fingerprint[:16] + " vws:vol=" + strings.TrimPrefix(vol.ID.String(), "vol-")
	vm, cfg, err := b.snapshotVolumeOwner(ctx, m.Scope, vol.ID, name, marker)
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	id, err := ids.Snapshot(configUUID(cfg), name)
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, resource.Invalid("volumeId", "snapshot requires a VM UUID")
	}
	rows, err := b.client.Snapshots(ctx, vm)
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, fmt.Errorf("proxmox: check snapshot replay: %w", err)
	}
	// The task can be accepted before PVE publishes its snapshot marker.
	exists := slices.ContainsFunc(rows, func(row pveclient.Snapshot) bool { return row.Name == name })
	if cfg.Lock == "snapshot" && !exists {
		upid, err := b.client.ActiveSnapshotTask(ctx, vm)
		if err != nil {
			return resource.Accepted[resource.Snapshot]{}, err
		}
		if upid != "" {
			if err := b.client.WaitTask(ctx, pveclient.Task{Node: vm.Node, UPID: upid}, pveclient.CloneWait); err != nil {
				return resource.Accepted[resource.Snapshot]{}, fmt.Errorf("proxmox: await snapshot marker: %w", err)
			}
		}
		rows, err = b.client.Snapshots(ctx, vm)
		if err != nil {
			return resource.Accepted[resource.Snapshot]{}, fmt.Errorf("proxmox: read completed snapshot marker: %w", err)
		}
		if !slices.ContainsFunc(rows, func(row pveclient.Snapshot) bool { return row.Name == name }) {
			return resource.Accepted[resource.Snapshot]{}, resource.Conflict(resource.KindVolume,
				vol.ID.String(), "snapshot task finished without publishing its marker")
		}
	}
	for _, row := range rows {
		if row.Name != name {
			continue
		}
		first, _, _ := strings.Cut(row.Description, "\n")
		if first != marker || row.VMState != 0 {
			return resource.Accepted[resource.Snapshot]{}, resource.IdempotencyMismatch()
		}
		snap := resource.Snapshot{
			ID: id, OwnerID: m.Account, VolumeID: vol.ID, VolumeSize: vol.SizeGiB,
			State: resource.SnapshotCompleted, Description: req.Description, Tags: req.Tags,
		}
		return snapshotAccepted(m.Scope, m.Key, snap, resource.OperationSucceeded)
	}
	for key, value := range req.Tags {
		if _, err := EncodeTag(key, value); err != nil {
			return resource.Accepted[resource.Snapshot]{}, err
		}
	}
	description, err := WithDescriptionTags(marker+"\n"+req.Description, req.Tags)
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	if _, err := b.client.CreateSnapshot(ctx, vm, name, description); err != nil {
		return resource.Accepted[resource.Snapshot]{}, fmt.Errorf("proxmox: create snapshot: %w", err)
	}
	snap := resource.Snapshot{
		ID: id, OwnerID: m.Account, VolumeID: vol.ID, VolumeSize: vol.SizeGiB,
		State: resource.SnapshotPending, Description: req.Description, Tags: req.Tags,
	}
	return snapshotAccepted(m.Scope, m.Key, snap, resource.OperationRunning)
}

func (b *Backend) snapshotVolumeOwner(
	ctx context.Context, s backend.Scope, id resource.VolumeID, name, marker string,
) (pveclient.VM, pveclient.VMConfig, error) {
	vms, err := b.poolVMs(ctx, s)
	if err != nil {
		return pveclient.VM{}, pveclient.VMConfig{}, err
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return pveclient.VM{}, pveclient.VMConfig{}, err
	}
	var owner pveclient.VM
	var ownerConfig pveclient.VMConfig
	for _, vm := range vms {
		target := pveclient.VM{Node: vm.Node, VMID: vm.VMID}
		cfg, err := b.client.VMConfig(ctx, target)
		if err != nil {
			return pveclient.VM{}, pveclient.VMConfig{}, fmt.Errorf("proxmox: read snapshot volume owner: %w", err)
		}
		if cfg.Template == 1 {
			continue
		}
		rows, err := b.client.Snapshots(ctx, target)
		if err != nil {
			return pveclient.VM{}, pveclient.VMConfig{}, fmt.Errorf("proxmox: find snapshot replay owner: %w", err)
		}
		for _, row := range rows {
			if row.Name == name {
				first, _, _ := strings.Cut(row.Description, "\n")
				if first != marker || row.VMState != 0 {
					return pveclient.VM{}, pveclient.VMConfig{}, resource.IdempotencyMismatch()
				}
				return target, cfg, nil
			}
		}
		volumes, err := b.vmVolumes(ctx, s, ids, vm, cfg, map[string][]pveclient.StorageContent{})
		if err != nil {
			return pveclient.VM{}, pveclient.VMConfig{}, err
		}
		for _, vol := range volumes {
			if vol.ID == id {
				owner, ownerConfig = target, cfg
			}
		}
	}
	if owner.VMID != 0 {
		return owner, ownerConfig, nil
	}
	return pveclient.VM{}, pveclient.VMConfig{}, resource.NotFound(resource.KindVolume, id.String())
}

func snapshotAccepted(
	s backend.Scope, key string, snap resource.Snapshot, state resource.OperationState,
) (resource.Accepted[resource.Snapshot], error) {
	sum := sha256.Sum256([]byte(key))
	id, err := (syncOperation{
		action: resource.ActionCreateSnapshot, kind: resource.KindSnapshot,
		local: strings.TrimPrefix(snap.ID.String(), "snap-"), keyHash: [8]byte(sum[:8]),
	}).encode()
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	return resource.Accepted[resource.Snapshot]{
		Operation: resource.Operation{
			ID: id, OwnerID: s.Account, Action: resource.ActionCreateSnapshot, State: state,
			Targets: []resource.Ref{snap.ID.Ref()},
		},
		Items: []resource.Snapshot{snap},
	}, nil
}

func (b *Backend) snapshotCreateOperation(
	ctx context.Context, s backend.Scope, id resource.OperationID, op syncOperation,
) (resource.Operation, error) {
	vms, err := b.poolVMs(ctx, s)
	if err != nil {
		return resource.Operation{}, err
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return resource.Operation{}, err
	}
	name := fmt.Sprintf("vws-%x", op.keyHash)
	for _, vm := range vms {
		target := pveclient.VM{Node: vm.Node, VMID: vm.VMID}
		cfg, err := b.client.VMConfig(ctx, target)
		if err != nil {
			return resource.Operation{}, fmt.Errorf("proxmox: read snapshot operation owner: %w", err)
		}
		snapshot, err := ids.Snapshot(configUUID(cfg), name)
		if err != nil || cfg.Template == 1 || strings.TrimPrefix(snapshot.String(), "snap-") != op.local {
			continue
		}
		rows, err := b.client.Snapshots(ctx, target)
		if err != nil {
			return resource.Operation{}, fmt.Errorf("proxmox: read snapshot operation: %w", err)
		}
		out := resource.Operation{
			ID: id, OwnerID: s.Account, Action: op.action,
			State: resource.OperationRunning, Targets: []resource.Ref{snapshot.Ref()},
		}
		for _, row := range rows {
			if row.Name == name && row.VMState == 0 {
				out.State = resource.OperationSucceeded
				return out, nil
			}
		}
		if cfg.Lock == "snapshot" {
			return out, nil
		}
		upid, err := b.client.ActiveSnapshotTask(ctx, target)
		if err != nil {
			return resource.Operation{}, err
		}
		if upid == "" {
			out.State, out.Error = resource.OperationFailed, resource.NotFound(resource.KindSnapshot, snapshot.String())
		}
		return out, nil
	}
	return resource.Operation{}, resource.NotFound(resource.KindOperation, id.String())
}
