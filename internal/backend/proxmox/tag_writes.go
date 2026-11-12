package proxmox

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func firstTagID[T any](ids []T) (id T) {
	if len(ids) != 0 {
		id = ids[0]
	}
	return id
}

// CreateTags merges user tags into pool-owned instances.
func (b *Backend) CreateTags(
	ctx context.Context, m backend.Mutation, req resource.CreateTagsRequest,
) (resource.Accepted[resource.Instance], error) {
	if _, err := b.vmForMutation(ctx, m.Scope, firstTagID(req.IDs)); err != nil || b.cfg.ReadOnly {
		if b.cfg.ReadOnly {
			return resource.Accepted[resource.Instance]{}, resource.Unsupported("CreateTags", "read-only")
		}
		return resource.Accepted[resource.Instance]{}, err
	}
	if _, err := req.Normalize(); err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	return b.editInstanceTags(ctx, m.Scope, m.Key, req.IDs, req.Tags, nil)
}

// DeleteTags removes selected user tags without changing system tags.
func (b *Backend) DeleteTags(
	ctx context.Context, m backend.Mutation, req resource.DeleteTagsRequest,
) (resource.Accepted[resource.Instance], error) {
	if _, err := b.vmForMutation(ctx, m.Scope, firstTagID(req.IDs)); err != nil || b.cfg.ReadOnly {
		if b.cfg.ReadOnly {
			return resource.Accepted[resource.Instance]{}, resource.Unsupported("DeleteTags", "read-only")
		}
		return resource.Accepted[resource.Instance]{}, err
	}
	if _, err := req.Normalize(); err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	return b.editInstanceTags(ctx, m.Scope, m.Key, req.IDs, nil, req.Tags)
}

// TagVolumes stores volume tags on the owning instance or holder VM.
func (b *Backend) TagVolumes(
	ctx context.Context, m backend.Mutation, req resource.TagVolumesRequest,
) (resource.Accepted[resource.Volume], error) {
	if _, err := b.volumeForMutation(ctx, m.Scope, firstTagID(req.IDs)); err != nil || b.cfg.ReadOnly {
		if b.cfg.ReadOnly {
			return resource.Accepted[resource.Volume]{}, resource.Unsupported("CreateTags", "read-only")
		}
		return resource.Accepted[resource.Volume]{}, err
	}
	if _, err := req.Normalize(); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	return b.editVolumeTags(ctx, m.Scope, m.Key, req.IDs, req.Tags, nil)
}

// UntagVolumes removes selected tags from pool-owned volumes.
func (b *Backend) UntagVolumes(
	ctx context.Context, m backend.Mutation, req resource.UntagVolumesRequest,
) (resource.Accepted[resource.Volume], error) {
	if _, err := b.volumeForMutation(ctx, m.Scope, firstTagID(req.IDs)); err != nil || b.cfg.ReadOnly {
		if b.cfg.ReadOnly {
			return resource.Accepted[resource.Volume]{}, resource.Unsupported("DeleteTags", "read-only")
		}
		return resource.Accepted[resource.Volume]{}, err
	}
	if _, err := req.Normalize(); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	return b.editVolumeTags(ctx, m.Scope, m.Key, req.IDs, nil, req.Tags)
}

type tagWriteTarget struct {
	vm     pveclient.VM
	ref    resource.Ref
	prefix string
}

func (b *Backend) editInstanceTags(
	ctx context.Context, s backend.Scope, key string, ids []resource.InstanceID,
	add map[string]string, remove []resource.TagSelector,
) (resource.Accepted[resource.Instance], error) {
	var targets []tagWriteTarget
	for _, id := range ids {
		vm, err := b.vmForMutation(ctx, s, id)
		if err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
		targets = append(targets, tagWriteTarget{vm: pveclient.VM{Node: vm.Node, VMID: vm.VMID}, ref: id.Ref()})
	}
	op, err := b.writeResourceTags(ctx, s, key, targets, add, remove)
	if err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	page, err := b.DescribeInstances(ctx, s, resource.InstanceQuery{IDs: ids})
	return resource.Accepted[resource.Instance]{Operation: op, Items: page.Items}, err
}

func (b *Backend) editVolumeTags(
	ctx context.Context, s backend.Scope, key string, ids []resource.VolumeID,
	add map[string]string, remove []resource.TagSelector,
) (resource.Accepted[resource.Volume], error) {
	for _, id := range ids {
		if _, err := b.volumeForMutation(ctx, s, id); err != nil {
			return resource.Accepted[resource.Volume]{}, err
		}
	}
	vms, err := b.poolVMs(ctx, s)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	codec, err := NewIDs(b.cluster)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	resolved := map[resource.VolumeID]tagWriteTarget{}
	var readErr error
	for _, vm := range vms {
		target := pveclient.VM{Node: vm.Node, VMID: vm.VMID}
		cfg, err := b.client.VMConfig(ctx, target)
		if err != nil {
			if ctx.Err() != nil {
				return resource.Accepted[resource.Volume]{}, err
			}
			slog.WarnContext(ctx, "skipping unreadable volume tag VM", slog.Int("vmid", vm.VMID), slog.Any("error", err))
			readErr = err
			continue
		}
		for drive, text := range cfg.Drives {
			if diskDevice(drive) == "" || option(text, "media") == "cdrom" {
				continue
			}
			storage, name, _ := strings.Cut(strings.SplitN(text, ",", 2)[0], ":")
			serial, err := url.QueryUnescape(option(text, "serial"))
			if err != nil {
				continue
			}
			volume, _, err := codec.Volume(serial, storage, name)
			if err == nil && slices.Contains(ids, volume) {
				resolved[volume] = tagWriteTarget{
					vm: target, ref: volume.Ref(),
					prefix: "vws.vt." + strings.TrimPrefix(volume.String(), "vol-")[:8] + ".",
				}
			}
		}
		if len(resolved) == len(ids) {
			break
		}
	}
	var targets []tagWriteTarget
	for _, id := range ids {
		target, found := resolved[id]
		if !found {
			if readErr != nil {
				return resource.Accepted[resource.Volume]{}, readErr
			}
			return resource.Accepted[resource.Volume]{}, resource.NotFound(resource.KindVolume, id.String())
		}
		targets = append(targets, target)
	}
	op, err := b.writeResourceTags(ctx, s, key, targets, add, remove)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	page, err := b.DescribeVolumes(ctx, s, resource.VolumeQuery{IDs: ids})
	return resource.Accepted[resource.Volume]{Operation: op, Items: page.Items}, err
}

func tagConfig(
	cfg pveclient.VMConfig, prefix string, add map[string]string, remove []resource.TagSelector,
) (string, string, error) {
	for _, sel := range remove {
		if _, err := EncodeTag(sel.Key, ""); err != nil {
			return "", "", err
		}
	}
	stored := strings.FieldsFunc(cfg.Tags, func(r rune) bool { return r == ';' })
	description := cfg.Description
	var kept, encoded []string
	if prefix != "" {
		for _, tag := range stored {
			rest, match := strings.CutPrefix(tag, prefix)
			if _, _, valid := DecodeTag(userTagPrefix + rest); match && valid {
				encoded = append(encoded, userTagPrefix+rest)
			} else {
				kept = append(kept, tag)
			}
		}
		description = ""
	} else {
		encoded = stored
	}
	tags, err := ReadTags(encoded, description)
	if err != nil {
		return "", "", fmt.Errorf("proxmox: read tags before write: %w", err)
	}
	var merged map[string]string
	if add != nil {
		merged, err = resource.MergeTags(tags.User, add)
		if err != nil {
			return "", "", err
		}
	} else {
		merged = resource.RemoveTags(tags.User, remove)
	}
	inline, overflow, err := Split(merged)
	if err != nil {
		return "", "", err
	}
	if prefix != "" {
		if len(overflow) != 0 {
			return "", "", resource.TagLimitExceeded("tags", "volume tags must fit in 128 encoded characters")
		}
		for _, tag := range inline {
			tag = prefix + strings.TrimPrefix(tag, userTagPrefix)
			if len(tag) > maxTagLen {
				return "", "", resource.TagLimitExceeded("tags", "volume tags must fit in 128 encoded characters")
			}
			kept = append(kept, tag)
		}
		return strings.Join(kept, ";"), cfg.Description, nil
	}
	description, err = WithDescriptionTags(cfg.Description, overflow)
	if len(description) > 8192 {
		return "", "", resource.TagLimitExceeded("tags", "tag overflow exceeds the 8192-byte VM description limit")
	}
	inline = append(inline, tags.System...)
	inline = append(inline, tags.Other...)
	return strings.Join(inline, ";"), description, err
}

func (b *Backend) writeResourceTags(
	ctx context.Context, s backend.Scope, key string, targets []tagWriteTarget,
	add map[string]string, remove []resource.TagSelector,
) (resource.Operation, error) {
	// Validate every target's resulting tag budget before writing any target.
	for _, target := range targets {
		cfg, err := b.client.VMConfig(ctx, target.vm)
		if err != nil {
			return resource.Operation{}, err
		}
		if _, _, err := tagConfig(cfg, target.prefix, add, remove); err != nil {
			return resource.Operation{}, err
		}
	}
	for _, target := range targets {
		for attempt := range 2 {
			cfg, err := b.client.VMConfig(ctx, target.vm)
			if err != nil {
				return resource.Operation{}, err
			}
			tags, description, err := tagConfig(cfg, target.prefix, add, remove)
			if err != nil {
				return resource.Operation{}, err
			}
			err = b.client.WriteConfigTags(ctx, target.vm, cfg.Digest, tags, description)
			if pveclient.DigestConflict(err) {
				if attempt == 0 {
					continue
				}
				return resource.Operation{}, resource.Conflict(resource.KindOperation, "", "config changed during tag write")
			}
			if err != nil {
				return resource.Operation{}, fmt.Errorf("proxmox: write resource tags: %w", err)
			}
			break
		}
	}
	action := resource.ActionDeleteTags
	if add != nil {
		action = resource.ActionCreateTags
	}
	first := targets[0].ref
	_, local, _ := strings.Cut(first.ID(), "-")
	hash := sha256.Sum256([]byte(key))
	id, err := (syncOperation{action: action, kind: first.Kind(), local: local, keyHash: [8]byte(hash[:8])}).encode()
	return resource.Operation{
		ID: id, Action: action, State: resource.OperationSucceeded,
		OwnerID: s.Account, Targets: []resource.Ref{first},
	}, err
}

func (b *Backend) tagOperation(
	ctx context.Context, s backend.Scope, id resource.OperationID,
) (resource.Operation, error) {
	decoded, err := decodeOperation(id)
	op, ok := decoded.(syncOperation)
	actions := []resource.Action{resource.ActionCreateTags, resource.ActionDeleteTags}
	if err != nil || !ok || !slices.Contains(actions, op.action) ||
		(op.kind != resource.KindInstance && op.kind != resource.KindVolume) {
		return resource.Operation{}, resource.NotFound(resource.KindOperation, id.String())
	}
	var ref resource.Ref
	if op.kind == resource.KindInstance {
		target, parseErr := resource.Parse[resource.InstanceID]("i-" + op.local)
		if parseErr != nil {
			return resource.Operation{}, parseErr
		}
		_, err = b.vmForMutation(ctx, s, target)
		ref = target.Ref()
	} else {
		target, parseErr := resource.Parse[resource.VolumeID]("vol-" + op.local)
		if parseErr != nil {
			return resource.Operation{}, parseErr
		}
		_, err = b.volumeForMutation(ctx, s, target)
		ref = target.Ref()
	}
	if err != nil {
		if resource.CodeOf(err) != resource.CodeNotFound {
			return resource.Operation{}, err
		}
		return resource.Operation{}, resource.NotFound(resource.KindOperation, id.String())
	}
	return resource.Operation{
		ID: id, Action: op.action, State: resource.OperationSucceeded,
		OwnerID: s.Account, Targets: []resource.Ref{ref},
	}, nil
}
