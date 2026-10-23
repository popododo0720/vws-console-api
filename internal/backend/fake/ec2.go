package fake

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/popododo0720/vws-console-api/internal/sshkey"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (c compute) StartInstances(ctx context.Context, m backend.Mutation, req resource.StartInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	return c.changeInstances(ctx, m, resource.ActionStartInstances, req.IDs)
}

func (c compute) TerminateInstances(ctx context.Context, m backend.Mutation, req resource.TerminateInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	return c.changeInstances(ctx, m, resource.ActionTerminateInstances, req.IDs)
}

func (c compute) CreateTags(ctx context.Context, m backend.Mutation, req resource.CreateTagsRequest) (resource.Accepted[resource.Instance], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Instance]](c.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	merged := make([]map[string]string, 0, len(req.IDs))
	targets := make([]resource.Ref, 0, len(req.IDs))
	for _, id := range req.IDs {
		inst, ok := c.w.inst[id]
		if !ok || inst.OwnerID != m.Account {
			return resource.Accepted[resource.Instance]{}, resource.NotFound(resource.KindInstance, id.String())
		}
		tags, err := resource.MergeTags(inst.Tags, req.Tags)
		if err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
		merged = append(merged, tags)
		targets = append(targets, id.Ref())
	}
	op, err := c.w.newOp(m.Account, resource.ServiceCompute, resource.ActionCreateTags, targets, func(time.Time) {})
	if err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	items := make([]resource.Instance, 0, len(req.IDs))
	for i, id := range req.IDs {
		inst := c.w.inst[id]
		inst.Tags = merged[i]
		items = append(items, *inst)
	}
	acc := resource.Accepted[resource.Instance]{Operation: op, Items: items}
	c.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (c compute) changeInstances(ctx context.Context, m backend.Mutation, action resource.Action, ids []resource.InstanceID) (resource.Accepted[resource.InstanceStateChange], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.InstanceStateChange]](c.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	type plan struct {
		inst *resource.Instance
		prev resource.InstanceState
		mid  resource.InstanceState
	}
	plans := make([]plan, 0, len(ids))
	changes := make([]resource.InstanceStateChange, 0, len(ids))
	targets := make([]resource.Ref, 0, len(ids))
	for _, id := range ids {
		inst, ok := c.w.inst[id]
		if !ok || inst.OwnerID != m.Account {
			return resource.Accepted[resource.InstanceStateChange]{}, resource.NotFound(resource.KindInstance, id.String())
		}
		mid, _, err := resource.NextInstanceState(action, inst.State)
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		plans = append(plans, plan{inst: inst, prev: inst.State, mid: mid})
		changes = append(changes, resource.InstanceStateChange{
			ID: id, OwnerID: inst.OwnerID, Previous: inst.State, Current: mid,
		})
		targets = append(targets, id.Ref())
	}
	for _, item := range plans {
		item.inst.State = item.mid
	}
	op, err := c.w.newOp(m.Account, resource.ServiceCompute, action, targets, func(time.Time) {
		for _, ch := range changes {
			inst := c.w.inst[ch.ID]
			if inst == nil {
				continue
			}
			_, settled, err := resource.NextInstanceState(action, ch.Previous)
			if err != nil {
				continue
			}
			if inst.State == ch.Current {
				inst.State = settled
			}
			if inst.State == resource.InstanceTerminated {
				c.w.dropRootVolumes(inst.ID)
			}
		}
	})
	if err != nil {
		for _, item := range plans {
			if item.inst.State == item.mid {
				item.inst.State = item.prev
			}
		}
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	acc := resource.Accepted[resource.InstanceStateChange]{Operation: op, Items: changes}
	c.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (c compute) CreateVolume(ctx context.Context, m backend.Mutation, req resource.CreateVolumeRequest) (resource.Accepted[resource.Volume], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	if !req.Type.Valid() {
		return resource.Accepted[resource.Volume]{}, resource.Invalid("volumeType", "unsupported")
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Volume]](c.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	if !req.SnapshotID.IsZero() {
		snap, ok := c.w.snap[req.SnapshotID]
		if !ok || snap.OwnerID != m.Account {
			return resource.Accepted[resource.Volume]{}, resource.NotFound(resource.KindSnapshot, req.SnapshotID.String())
		}
		if snap.State != resource.SnapshotCompleted {
			return resource.Accepted[resource.Volume]{}, resource.Conflict(resource.KindSnapshot, req.SnapshotID.String(), "snapshot is not completed")
		}
		if req.SizeGiB == 0 {
			req.SizeGiB = snap.VolumeSize
		}
		if req.SizeGiB < snap.VolumeSize {
			return resource.Accepted[resource.Volume]{}, resource.Invalid("size", "smaller than the snapshot")
		}
	}
	id, err := resource.Mint[resource.VolumeID](c.w.entropy)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	if _, exists := c.w.vol[id]; exists {
		return resource.Accepted[resource.Volume]{}, resource.Internal(errors.New("identifier collision"))
	}
	vol := resource.Volume{
		ID: id, OwnerID: m.Account, SizeGiB: req.SizeGiB, Zone: req.Zone, Type: req.Type, State: resource.VolumeCreating,
		SnapshotID: req.SnapshotID, CreateTime: c.w.now().UTC(),
	}
	op, err := c.w.newOp(m.Account, resource.ServiceCompute, resource.ActionCreateVolume, []resource.Ref{id.Ref()}, func(time.Time) {
		if cur := c.w.vol[id]; cur != nil && cur.State == resource.VolumeCreating {
			cur.State = resource.VolumeAvailable
		}
	})
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	stored := vol
	c.w.vol[id] = &stored
	acc := resource.Accepted[resource.Volume]{Operation: op, Items: []resource.Volume{vol}}
	c.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (c compute) AttachVolume(ctx context.Context, m backend.Mutation, req resource.AttachVolumeRequest) (resource.Accepted[resource.Volume], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Volume]](c.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	vol, ok := c.w.vol[req.VolumeID]
	if !ok || vol.OwnerID != m.Account {
		return resource.Accepted[resource.Volume]{}, resource.NotFound(resource.KindVolume, req.VolumeID.String())
	}
	inst, ok := c.w.inst[req.InstanceID]
	if !ok || inst.OwnerID != m.Account {
		return resource.Accepted[resource.Volume]{}, resource.NotFound(resource.KindInstance, req.InstanceID.String())
	}
	if vol.State != resource.VolumeAvailable {
		return resource.Accepted[resource.Volume]{}, resource.VolumeNotAvailable(vol.ID)
	}
	if inst.State != resource.InstanceRunning && inst.State != resource.InstanceStopped {
		return resource.Accepted[resource.Volume]{}, resource.Conflict(resource.KindInstance, inst.ID.String(), "instance cannot accept a volume from "+inst.State.String())
	}
	prev := *vol
	prevBlocks := append([]resource.BlockDevice(nil), inst.BlockDevices...)
	// The volume is in-use from the accept, as on EC2. The attachment is
	// attaching until the operation settles, which stands in for the
	// hypervisor plugging the disk in.
	vol.State = resource.VolumeInUse
	vol.InstanceID = req.InstanceID
	vol.Device = req.Device
	vol.AttachTime = c.w.now().UTC()
	vol.AttachState = resource.AttachmentAttaching
	inst.BlockDevices = append(inst.BlockDevices, resource.BlockDevice{Device: req.Device, VolumeID: req.VolumeID})
	volID, instID, attachedAt := vol.ID, req.InstanceID, vol.AttachTime
	targets := []resource.Ref{vol.ID.Ref()}
	op, err := c.w.newOp(m.Account, resource.ServiceCompute, resource.ActionAttachVolume, targets, func(time.Time) {
		// After a detach, or a detach and a new attach, the volume no longer
		// holds this attachment, so it is left alone.
		cur := c.w.vol[volID]
		if cur != nil && cur.InstanceID == instID && cur.AttachTime.Equal(attachedAt) &&
			cur.AttachState == resource.AttachmentAttaching {
			cur.AttachState = resource.AttachmentAttached
		}
	})
	if err != nil {
		*vol = prev
		inst.BlockDevices = prevBlocks
		return resource.Accepted[resource.Volume]{}, err
	}
	item := *vol
	acc := resource.Accepted[resource.Volume]{Operation: op, Items: []resource.Volume{item}}
	c.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (c compute) DetachVolume(
	ctx context.Context, m backend.Mutation, req resource.DetachVolumeRequest,
) (resource.Accepted[resource.VolumeAttachment], error) {
	var zero resource.Accepted[resource.VolumeAttachment]
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.VolumeAttachment]](c.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	vol, ok := c.w.vol[req.VolumeID]
	if !ok || vol.OwnerID != m.Account {
		return zero, resource.NotFound(resource.KindVolume, req.VolumeID.String())
	}
	inst, bind, found := c.w.bindOfVolume(m.Account, vol.ID)
	if !found {
		return zero, resource.VolumeNotInUse(vol.ID)
	}
	// A wrong instance or device is not this attachment, including on the root
	// device. DropBind would otherwise report the root conflict first.
	if !req.InstanceID.IsZero() && req.InstanceID != bind.InstanceID {
		return zero, resource.AttachmentNotFound(vol.ID)
	}
	if req.Device != "" && req.Device != bind.Device {
		return zero, resource.AttachmentNotFound(vol.ID)
	}
	// The gRPC backend keeps a replay record per client-token detach on the
	// instance, within a label budget; the fake holds the same budget.
	now := c.w.now()
	if !m.MintedToken && c.w.detachesInWindow(inst.ID, vol.ID, now) >= backend.MaxDetachReplays {
		return zero, backend.DetachReplaysExhausted(inst.ID)
	}
	next, _, err := backend.DropBind(*inst, vol.ID)
	if err != nil {
		return zero, err
	}
	prevVol := *vol
	prevBlocks := inst.BlockDevices
	inst.BlockDevices = next.BlockDevices
	attachedAt := vol.AttachTime
	vol.State = resource.VolumeAvailable
	vol.InstanceID = resource.InstanceID{}
	vol.Device = ""
	vol.AttachTime = time.Time{}
	vol.AttachState = ""
	op, err := c.w.newOp(
		m.Account, resource.ServiceCompute, resource.ActionDetachVolume,
		[]resource.Ref{inst.ID.Ref()}, func(time.Time) {},
	)
	if err != nil {
		*vol = prevVol
		inst.BlockDevices = prevBlocks
		return zero, err
	}
	item := resource.VolumeAttachment{
		VolumeID: vol.ID, OwnerID: vol.OwnerID, InstanceID: bind.InstanceID, Device: bind.Device,
		Status: resource.AttachmentDetaching, AttachTime: attachedAt,
	}
	acc := resource.Accepted[resource.VolumeAttachment]{Operation: op, Items: []resource.VolumeAttachment{item}}
	if !m.MintedToken {
		if c.w.detached[inst.ID] == nil {
			c.w.detached[inst.ID] = map[resource.VolumeID]time.Time{}
		}
		c.w.detached[inst.ID][vol.ID] = now
	}
	c.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

// detachesInWindow forgets the client-token detaches of inst that have
// expired (backend.ClientTokenExpired) and counts the others, except one of skip,
// which a new detach of the same volume replaces.
func (w *World) detachesInWindow(inst resource.InstanceID, skip resource.VolumeID, now time.Time) int {
	n := 0
	for vol, at := range w.detached[inst] {
		if backend.ClientTokenExpired(at, now) {
			delete(w.detached[inst], vol)
			continue
		}
		if vol != skip {
			n++
		}
	}
	return n
}

func (w *World) bindOfVolume(
	account resource.AccountID, id resource.VolumeID,
) (*resource.Instance, backend.VolumeBind, bool) {
	for _, inst := range w.inst {
		if inst.OwnerID != account {
			continue
		}
		if bind, ok := backend.BindOf(*inst, id); ok {
			return inst, bind, true
		}
	}
	return nil, backend.VolumeBind{}, false
}

func (c compute) DeleteVolume(ctx context.Context, m backend.Mutation, req resource.DeleteVolumeRequest) (resource.Accepted[resource.Volume], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Volume]](c.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	vol, ok := c.w.vol[req.ID]
	if !ok || vol.OwnerID != m.Account {
		return resource.Accepted[resource.Volume]{}, resource.NotFound(resource.KindVolume, req.ID.String())
	}
	// Storage rejects a delete while an instance spec still names the volume.
	// State is only the projection attach and detach keep beside that list.
	if c.w.volumeOnInstance(vol.ID) {
		return resource.Accepted[resource.Volume]{}, resource.Conflict(resource.KindVolume, vol.ID.String(), "volume is in use")
	}
	prev := vol.State
	vol.State = resource.VolumeDeleting
	id := vol.ID
	op, err := c.w.newOp(m.Account, resource.ServiceCompute, resource.ActionDeleteVolume, []resource.Ref{id.Ref()}, func(time.Time) {
		if cur := c.w.vol[id]; cur != nil && cur.State == resource.VolumeDeleting {
			delete(c.w.vol, id)
		}
	})
	if err != nil {
		vol.State = prev
		return resource.Accepted[resource.Volume]{}, err
	}
	item := *vol
	acc := resource.Accepted[resource.Volume]{Operation: op, Items: []resource.Volume{item}}
	c.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (c compute) ModifyVolume(ctx context.Context, m backend.Mutation, req resource.ModifyVolumeRequest) (resource.Accepted[resource.Volume], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Volume]](c.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	vol, ok := c.w.vol[req.ID]
	if !ok || vol.OwnerID != m.Account {
		return resource.Accepted[resource.Volume]{}, resource.NotFound(resource.KindVolume, req.ID.String())
	}
	if req.SizeGiB < vol.SizeGiB {
		return resource.Accepted[resource.Volume]{}, resource.Invalid("size", "a volume cannot shrink")
	}
	id, size := vol.ID, req.SizeGiB
	op, err := c.w.newOp(m.Account, resource.ServiceCompute, resource.ActionModifyVolume, []resource.Ref{id.Ref()}, func(time.Time) {
		if cur := c.w.vol[id]; cur != nil {
			cur.SizeGiB = size
		}
	})
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	item := *vol
	item.SizeGiB = size
	acc := resource.Accepted[resource.Volume]{Operation: op, Items: []resource.Volume{item}}
	c.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (c compute) DescribeVolumes(ctx context.Context, s backend.Scope, q resource.VolumeQuery) (resource.Page[resource.Volume], error) {
	if err := ctx.Err(); err != nil {
		return resource.Page[resource.Volume]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	return pageOwned(c.w.vol, s.Account, q.IDs, q.Page, resource.KindVolume)
}

func (c compute) DescribeImages(ctx context.Context, s backend.Scope, q resource.ImageQuery) (resource.Page[resource.Image], error) {
	if err := ctx.Err(); err != nil {
		return resource.Page[resource.Image]{}, err
	}
	known := resource.KnownImages(s.Account)
	want := map[resource.ImageID]struct{}{}
	for _, id := range q.IDs {
		want[id] = struct{}{}
	}
	var items []resource.Image
	for _, img := range known {
		if len(want) > 0 {
			if _, ok := want[img.ID]; !ok {
				continue
			}
		}
		items = append(items, img)
	}
	if len(q.IDs) == 1 && len(items) == 0 {
		return resource.Page[resource.Image]{}, resource.NotFound(resource.KindImage, q.IDs[0].String())
	}
	return page(items, q.Page)
}

func (c compute) CreateKeyPair(ctx context.Context, m backend.Mutation, req resource.CreateKeyPairRequest) (resource.Accepted[resource.KeyPair], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	// EC2 CreateKeyPair and ImportKeyPair take no client token. A create is
	// judged by the name alone: a live name is InvalidKeyPair.Duplicate, a
	// free one is a new key pair, whatever the token did before (#268). An
	// import retried under its token replays only while the key pair it made
	// still lives, so an in-flight retry makes no second key pair. After that
	// key pair is deleted, or for another key, it is judged by the name too
	// (#279). A generated create and an import under one token keep
	// separate records, as their compute request ids do over gRPC, so a
	// create never takes the record an import replays from (#281).
	record := keyPairRecord(m.Key, req.PublicKey != "")
	if req.PublicKey != "" {
		acc, ok, err := replay[resource.Accepted[resource.KeyPair]](c.w, record, m.Fingerprint)
		if err != nil && resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
			return acc, err
		}
		if ok && len(acc.Items) == 1 {
			if _, live := c.w.key[acc.Items[0].ID]; live {
				return acc, nil
			}
		}
	}
	for _, existing := range c.w.key {
		if existing.OwnerID == m.Account && existing.Name == req.Name {
			return resource.Accepted[resource.KeyPair]{}, resource.AlreadyExists(resource.KindKeyPair, req.Name)
		}
	}
	id, err := resource.Mint[resource.KeyPairID](c.w.entropy)
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	if _, exists := c.w.key[id]; exists {
		return resource.Accepted[resource.KeyPair]{}, resource.Internal(errors.New("identifier collision"))
	}
	key := resource.KeyPair{ID: id, OwnerID: m.Account, Name: req.Name, Type: req.Type}
	if req.PublicKey != "" {
		pub, err := sshkey.ParsePublic(req.PublicKey)
		if err != nil {
			return resource.Accepted[resource.KeyPair]{}, resource.Invalid("publicKeyMaterial", err.Error())
		}
		key.Fingerprint, key.Type = pub.AWSFingerprint, pub.Type
	} else {
		pair, err := sshkey.Generate(req.Type, c.w.entropy)
		if err != nil {
			return resource.Accepted[resource.KeyPair]{}, resource.Internal(err)
		}
		key.Fingerprint, key.Material = pair.AWSFingerprint, pair.Private
		if req.Format == resource.KeyFormatPPK {
			key.Material = pair.PPK(req.Name)
		}
	}
	op, err := c.w.newOp(m.Account, resource.ServiceCompute, resource.ActionCreateKeyPair, []resource.Ref{id.Ref()}, func(time.Time) {})
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	stored := key
	stored.Material = ""
	c.w.key[id] = &stored
	// The idempotency record keeps no private key.
	acc := resource.Accepted[resource.KeyPair]{Operation: op, Items: []resource.KeyPair{stored}}
	c.w.finish(record, m.Fingerprint, acc)
	return resource.Accepted[resource.KeyPair]{Operation: op, Items: []resource.KeyPair{key}}, nil
}

// keyPairRecord is the idempotency record key of a CreateKeyPair under
// token. Imports and generated creates get distinct keys (#281).
func keyPairRecord(token string, imported bool) string {
	if imported {
		return "key-import\x00" + token
	}
	return "key-create\x00" + token
}

func (n network) CreateVpc(ctx context.Context, m backend.Mutation, req resource.CreateVpcRequest) (resource.Accepted[resource.Vpc], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Vpc]](n.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	id, err := resource.Mint[resource.VpcID](n.w.entropy)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	if _, exists := n.w.vpc[id]; exists {
		return resource.Accepted[resource.Vpc]{}, resource.Internal(errors.New("identifier collision"))
	}
	vpc := resource.Vpc{ID: id, OwnerID: m.Account, Cidr: req.Cidr, State: resource.VpcPending, Tags: copyTags(req.Tags)}
	op, err := n.w.newOp(m.Account, resource.ServiceNetwork, resource.ActionCreateVpc, []resource.Ref{id.Ref()}, func(time.Time) {
		if cur := n.w.vpc[id]; cur != nil && cur.State == resource.VpcPending {
			cur.State = resource.VpcAvailable
		}
	})
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	stored := vpc
	stored.Tags = copyTags(vpc.Tags)
	n.w.vpc[id] = &stored
	acc := resource.Accepted[resource.Vpc]{Operation: op, Items: []resource.Vpc{vpc}}
	n.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (n network) DeleteVpc(ctx context.Context, m backend.Mutation, req resource.DeleteVpcRequest) (resource.Accepted[resource.Vpc], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Vpc]](n.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	vpc, ok := n.w.vpc[req.ID]
	if !ok || vpc.OwnerID != m.Account {
		return resource.Accepted[resource.Vpc]{}, resource.NotFound(resource.KindVpc, req.ID.String())
	}
	if n.w.vpcInUse(req.ID) {
		return resource.Accepted[resource.Vpc]{}, resource.Conflict(resource.KindVpc, req.ID.String(), "vpc has dependents")
	}
	prev := vpc.State
	vpc.State = resource.VpcDeleting
	id := vpc.ID
	op, err := n.w.newOp(m.Account, resource.ServiceNetwork, resource.ActionDeleteVpc, []resource.Ref{id.Ref()}, func(time.Time) {
		if cur := n.w.vpc[id]; cur != nil && cur.State == resource.VpcDeleting {
			delete(n.w.vpc, id)
		}
	})
	if err != nil {
		vpc.State = prev
		return resource.Accepted[resource.Vpc]{}, err
	}
	item := *vpc
	acc := resource.Accepted[resource.Vpc]{Operation: op, Items: []resource.Vpc{item}}
	n.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (n network) DescribeVpcs(ctx context.Context, s backend.Scope, q resource.VpcQuery) (resource.Page[resource.Vpc], error) {
	if err := ctx.Err(); err != nil {
		return resource.Page[resource.Vpc]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	return pageOwned(n.w.vpc, s.Account, q.IDs, q.Page, resource.KindVpc)
}

func (n network) CreateSecurityGroup(ctx context.Context, m backend.Mutation, req resource.CreateSecurityGroupRequest) (resource.Accepted[resource.SecurityGroup], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.SecurityGroup]](n.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	vpc, ok := n.w.vpc[req.VpcID]
	if !ok || vpc.OwnerID != m.Account {
		return resource.Accepted[resource.SecurityGroup]{}, resource.NotFound(resource.KindVpc, req.VpcID.String())
	}
	for _, existing := range n.w.sg {
		if existing.OwnerID == m.Account && existing.VpcID == req.VpcID && existing.Name == req.Name {
			return resource.Accepted[resource.SecurityGroup]{}, resource.AlreadyExists(resource.KindSecurityGroup, req.Name)
		}
	}
	id, err := resource.Mint[resource.SecurityGroupID](n.w.entropy)
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	if _, exists := n.w.sg[id]; exists {
		return resource.Accepted[resource.SecurityGroup]{}, resource.Internal(errors.New("identifier collision"))
	}
	group := resource.SecurityGroup{ID: id, OwnerID: m.Account, Name: req.Name, VpcID: req.VpcID}
	op, err := n.w.newOp(m.Account, resource.ServiceNetwork, resource.ActionCreateSecurityGroup, []resource.Ref{id.Ref()}, func(time.Time) {})
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	stored := group
	n.w.sg[id] = &stored
	acc := resource.Accepted[resource.SecurityGroup]{Operation: op, Items: []resource.SecurityGroup{group}}
	n.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (n network) AuthorizeSecurityGroupIngress(ctx context.Context, m backend.Mutation, req resource.AuthorizeSecurityGroupIngressRequest) (resource.Accepted[resource.SecurityGroup], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.SecurityGroup]](n.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	group, ok := n.w.sg[req.ID]
	if !ok || group.OwnerID != m.Account {
		return resource.Accepted[resource.SecurityGroup]{}, resource.NotFound(resource.KindSecurityGroup, req.ID.String())
	}
	for _, rule := range group.Rules {
		if rule == req.Rule {
			return resource.Accepted[resource.SecurityGroup]{}, resource.AlreadyExists(resource.KindSecurityGroup, req.ID.String())
		}
	}
	group.Rules = append(group.Rules, req.Rule)
	op, err := n.w.newOp(m.Account, resource.ServiceNetwork, resource.ActionAuthorizeSecurityGroupIngress, []resource.Ref{group.ID.Ref()}, func(time.Time) {})
	if err != nil {
		group.Rules = group.Rules[:len(group.Rules)-1]
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	item := *group
	item.Rules = append([]resource.IngressRule(nil), group.Rules...)
	acc := resource.Accepted[resource.SecurityGroup]{Operation: op, Items: []resource.SecurityGroup{item}}
	n.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (w *World) vpcInUse(id resource.VpcID) bool {
	for _, sub := range w.sub {
		if sub.VpcID == id {
			return true
		}
	}
	for _, group := range w.sg {
		if group.VpcID == id {
			return true
		}
	}
	return false
}

func pageOwned[I interface {
	comparable
	String() string
}, T resource.Owned](rows map[I]*T, account resource.AccountID, ids []I, q resource.PageRequest, kind resource.Kind) (resource.Page[T], error) {
	want := map[string]struct{}{}
	for _, id := range ids {
		want[id.String()] = struct{}{}
	}
	var items []T
	for _, row := range rows {
		item := *row
		if item.Owner() != account {
			continue
		}
		if len(want) > 0 {
			if _, ok := want[item.Identity()]; !ok {
				continue
			}
		}
		items = append(items, item)
	}
	sortOwned(items)
	if len(ids) == 1 && len(items) == 0 {
		return resource.Page[T]{}, resource.NotFound(kind, ids[0].String())
	}
	return page(items, q)
}

func sortOwned[T resource.Owned](items []T) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].Identity() < items[j-1].Identity(); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

func cidrInside(child, parent string) bool {
	ip, childNet, err := net.ParseCIDR(child)
	if err != nil || ip.To4() == nil {
		return false
	}
	_, parentNet, err := net.ParseCIDR(parent)
	if err != nil || !parentNet.Contains(childNet.IP) {
		return false
	}
	childOnes, childBits := childNet.Mask.Size()
	parentOnes, parentBits := parentNet.Mask.Size()
	return childBits == 32 && parentBits == 32 && childOnes > parentOnes
}

func (w *World) volumeOnInstance(id resource.VolumeID) bool {
	for _, inst := range w.inst {
		for _, block := range inst.BlockDevices {
			if block.VolumeID == id {
				return true
			}
		}
	}
	return false
}

// dropRootVolumes deletes the volumes that go with a terminated instance.
func (w *World) dropRootVolumes(id resource.InstanceID) {
	for volID, vol := range w.vol {
		if vol.InstanceID == id && vol.DeleteOnTermination {
			delete(w.vol, volID)
		}
	}
}
