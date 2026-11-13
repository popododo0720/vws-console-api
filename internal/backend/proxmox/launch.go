package proxmox

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// RunInstances records recovery inputs with each clone before returning pending instances.
func (b *Backend) RunInstances(
	ctx context.Context, m backend.Mutation, req resource.RunInstancesRequest,
) (resource.Accepted[resource.Instance], error) {
	pool, err := b.poolForMutation(ctx, m.Scope)
	var out resource.Accepted[resource.Instance]
	if b.cfg.ReadOnly {
		return out, resource.Unsupported("RunInstances", "read-only")
	}
	if err != nil {
		return out, err
	}
	if err := b.validateLaunch(req); err != nil {
		return out, err
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return out, err
	}
	// Serialize recovery and allocation so concurrent retries cannot create the same index twice.
	b.launchMu.Lock()
	defer b.launchMu.Unlock()
	recovered, err := b.RecoverLaunch(ctx, m.Scope, m.Key, m.Fingerprint)
	if err != nil && resource.CodeOf(err) != resource.CodeNotFound {
		return out, err
	}
	if err != nil {
		op, err := newLaunchOperation(b.cluster, m.Key)
		if err != nil {
			return out, err
		}
		id, err := op.encode()
		if err != nil {
			return out, err
		}
		reservation, err := ids.Reservation(m.Key)
		if err != nil {
			return out, err
		}
		recovered = LaunchRecovery{
			Instances: map[int]resource.InstanceID{}, Count: req.Count, Reservation: reservation,
			Operation: resource.Operation{
				ID: id, OwnerID: m.Account,
				Action: resource.ActionRunInstances, State: resource.OperationRunning,
			},
		}
	}
	if recovered.Count != req.Count {
		return out, resource.IdempotencyMismatch()
	}
	missing := req.Count - len(recovered.Instances)
	if missing > 0 && recovered.Operation.State != resource.OperationFailed {
		if err := b.allocateLaunch(ctx, m.Scope, pool, m.Key, m.Fingerprint, req, ids, &recovered); err != nil {
			return out, err
		}
	}
	out.Operation = recovered.Operation
	out.Operation.Targets = nil
	for index := range req.Count {
		id, exists := recovered.Instances[index]
		if !exists {
			continue
		}
		out.Items = append(out.Items, resource.Instance{
			ID: id, OwnerID: m.Account, ReservationID: recovered.Reservation,
			ImageID: req.ImageID, InstanceType: req.InstanceType, SubnetID: req.SubnetID,
			KeyName: req.KeyName, Tags: maps.Clone(req.Tags), State: resource.InstancePending,
		})
		out.Operation.Targets = append(out.Operation.Targets, id.Ref())
	}
	return out, nil
}

func (b *Backend) validateLaunch(req resource.RunInstancesRequest) error {
	if req.Count < 1 || req.Count > 10 {
		return resource.Invalid("count", "must be from 1 to 10")
	}
	typ, ok := ResolveInstanceType(req.InstanceType)
	if !ok {
		return resource.Invalid("instanceType", "unknown instance type")
	}
	if b.cfg.InstanceTypes != nil {
		if _, allowed := b.cfg.InstanceTypes[typ.Name]; !allowed {
			return resource.Invalid("instanceType", "instance type is not enabled")
		}
	}
	if len(req.UserData) > 32768 || !utf8.ValidString(req.UserData) {
		return resource.Invalid("UserData", "must be UTF-8 text of at most 32768 bytes")
	}
	if req.UserData != "" {
		return resource.Unsupported("UserData", "snippet dispatch is deferred to the next accept-path part")
	}
	if len(req.KeyName) > 255 || !utf8.ValidString(req.KeyName) ||
		strings.ContainsFunc(req.KeyName, unicode.IsControl) {
		return resource.Invalid("keyName", "malformed")
	}
	if _, err := resource.MergeTags(nil, req.Tags); err != nil {
		return err
	}
	for key, value := range req.Tags {
		if _, err := EncodeTag(key, value); err != nil {
			return err
		}
	}
	for _, field := range []struct {
		name string
		set  bool
	}{
		{"BlockDeviceMapping", len(req.ExtraVolumes) > 0},
		{"NetworkInterface", len(req.NetworkInterfaces) > 0},
		{"RootVolumeSize", req.RootVolumeSize != 0},
		{"RootIops", req.RootIops != 0},
		{"RootThroughput", req.RootThroughput != 0},
	} {
		if field.set {
			return resource.Unsupported(field.name, "not recorded by the clone accept path")
		}
	}
	if req.RootVolumeType != "" && !req.RootVolumeType.Valid() {
		return resource.Invalid("volumeType", "unsupported")
	}
	return nil
}

func (b *Backend) allocateLaunch(
	ctx context.Context, scope backend.Scope, pool, key, fingerprint string,
	req resource.RunInstancesRequest, ids IDs, recovered *LaunchRecovery,
) error {
	rows, err := b.client.ClusterResources(ctx, "")
	if err != nil {
		return fmt.Errorf("proxmox: launch inventory: %w", err)
	}
	source, cfg, err := b.launchTemplate(ctx, ids, rows, pool, req.ImageID)
	if err != nil {
		return err
	}
	if req.SubnetID.IsZero() {
		return resource.Invalid("subnetId", "required")
	}
	if _, err := b.DescribeSubnets(ctx, scope, resource.SubnetQuery{IDs: []resource.SubnetID{req.SubnetID}}); err != nil {
		return err
	}
	r, err := b.staticSubnet(req.SubnetID)
	if err != nil {
		return err
	}
	if r.prefix.IsValid() {
		used, pending, err := b.scanStaticIPs(ctx, req.SubnetID)
		if err != nil {
			return err
		}
		if _, err := r.free(used, pending+req.Count-len(recovered.Instances)); err != nil {
			return err
		}
	}
	storage := b.cfg.Storages[string(req.RootType())]
	if storage == "" {
		return resource.Unsupported("volumeType", "no configured storage for root volume type")
	}
	volid, _, _ := strings.Cut(cfg.Drives["scsi0"], ",")
	rootStorage, _, found := strings.Cut(volid, ":")
	if !found {
		return resource.Unsupported("ImageId", "template requires a scsi0 root disk")
	}
	disks, err := b.client.StorageContent(ctx, source.Node, rootStorage)
	if err != nil {
		return fmt.Errorf("proxmox: template root disk: %w", err)
	}
	var rootSize int64
	for _, disk := range disks {
		if disk.VolID == volid {
			rootSize = (disk.Size + (1 << 30) - 1) >> 30
		}
	}
	if rootSize <= 0 {
		return resource.Unsupported("ImageId", "template root disk size is unavailable")
	}
	templateNode := ""
	for _, drive := range cfg.Drives {
		diskStorage, _, ok := strings.Cut(drive, ":")
		if ok && !slices.ContainsFunc(rows, func(row pveclient.ClusterResource) bool {
			return row.Type == "storage" && row.Node == source.Node && row.Storage == diskStorage && row.Shared == 1
		}) {
			templateNode = source.Node
		}
	}
	placements, err := Schedule(rows, backend.ProxmoxRegion{Name: b.region, Zones: b.zones},
		PlacementRequest{
			InstanceType: req.InstanceType, TemplateNode: templateNode, Storage: storage,
			RootSizeGiB: int(rootSize), Count: req.Count - len(recovered.Instances),
		}, b.cfg.Scheduler)
	if err != nil {
		return err
	}
	description, err := WithDescriptionTags("", req.Tags)
	if err != nil {
		return err
	}
	type clone struct {
		index       int
		id          resource.InstanceID
		description string
	}
	var clones []clone
	for index := range req.Count {
		if _, exists := recovered.Instances[index]; exists {
			continue
		}
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return fmt.Errorf("proxmox: launch UUID: %w", err)
		}
		raw[6], raw[8] = raw[6]&0x0f|0x40, raw[8]&0x3f|0x80
		uuid := fmt.Sprintf("%x-%x-%x-%x-%x", raw[:4], raw[4:6], raw[6:8], raw[8:10], raw[10:])
		id, _, err := ids.Instance(VM{UUID: uuid})
		if err != nil {
			return err
		}
		serial, err := ids.RootVolumeSerial(uuid)
		if err != nil {
			return err
		}
		marker := LaunchMarker{
			UUID: uuid, Key: key, Fingerprint: fingerprint,
			Index: index, Count: req.Count, Account: scope.Account, Image: req.ImageID,
			Type: req.InstanceType, Subnet: req.SubnetID, KeyPair: req.KeyName, Attempt: 1,
			CreatedAt: b.launchNow().Unix(),
		}
		if r.prefix.IsValid() {
			marker.IPFence = fmt.Sprintf("%x", raw)
		}
		if !req.RootVolumeKept {
			marker.DOT = []string{serial[:8]}
		}
		marked, err := WithLaunchMarker(description, marker)
		if err != nil {
			return resource.Invalid("tags", "launch metadata exceeds the description budget")
		}
		clones = append(clones, clone{index, id, marked})
	}
	for i, clone := range clones {
		target := ""
		if templateNode == "" {
			target = placements[i].Node
		}
		name := strings.Trim(strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
				return r
			}
			return '-'
		}, req.Tags["Name"]), "-")
		if name == "" {
			name = clone.id.String()
		}
		name = strings.TrimRight(name[:min(len(name), 63)], "-")
		for attempt := 0; ; attempt++ {
			vmid, err := b.client.NextVolumeVMID(ctx)
			if err != nil {
				return err
			}
			_, err = b.client.Clone(ctx, source, vmid, pool, name, clone.description, target, !b.cfg.LinkedClones, storage)
			if err == nil {
				break
			}
			var he *pveclient.HTTPError
			if attempt == 3 || !errors.As(err, &he) || he.Status != http.StatusInternalServerError ||
				strings.TrimSpace(he.Message) != fmt.Sprintf("VM %d already exists", vmid) {
				return fmt.Errorf("proxmox: launch clone: %w", err)
			}
		}
		recovered.Instances[clone.index] = clone.id
	}
	return nil
}

func (b *Backend) launchTemplate(
	ctx context.Context, ids IDs, rows []pveclient.ClusterResource, pool string, image resource.ImageID,
) (pveclient.VM, pveclient.VMConfig, error) {
	// An unreadable template cannot be ruled out as the image, so its error replaces NotFound when nothing matches.
	var readErr error
	for _, row := range rows {
		public := b.cfg.Templates.Pool != "" && row.Pool == b.cfg.Templates.Pool ||
			b.cfg.Templates.Tag != "" && slices.Contains(strings.Split(row.Tags, ";"), b.cfg.Templates.Tag)
		if row.Type != "qemu" || row.Template != 1 || row.Pool != pool && !public {
			continue
		}
		vm := pveclient.VM{Node: row.Node, VMID: row.VMID}
		cfg, err := b.client.VMConfig(ctx, vm)
		if err != nil {
			err = fmt.Errorf("proxmox: template config: %w", err)
			if ctx.Err() != nil {
				return vm, cfg, err
			}
			if readErr == nil {
				readErr = err
			}
			continue
		}
		id, err := ids.Image(configUUID(cfg))
		if err == nil && id == image && cfg.Template == 1 {
			return vm, cfg, nil
		}
	}
	if readErr != nil {
		return pveclient.VM{}, pveclient.VMConfig{}, readErr
	}
	return pveclient.VM{}, pveclient.VMConfig{}, resource.NotFound(resource.KindImage, image.String())
}
