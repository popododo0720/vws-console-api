package fake

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (c compute) StartInstances(ctx context.Context, m backend.Mutation, req resource.StartInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	return c.changeInstances(ctx, m, resource.ActionStartInstances, req.IDs)
}

func (c compute) TerminateInstances(ctx context.Context, m backend.Mutation, req resource.TerminateInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	return c.changeInstances(ctx, m, resource.ActionTerminateInstances, req.IDs)
}

func (c compute) changeInstances(ctx context.Context, m backend.Mutation, action resource.Action, ids []resource.InstanceID) (resource.Accepted[resource.InstanceStateChange], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if hit, ok, err := c.w.begin(m.Key, m.Fingerprint); err != nil || ok {
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		acc, _ := hit.(resource.Accepted[resource.InstanceStateChange])
		return acc, nil
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
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if hit, ok, err := c.w.begin(m.Key, m.Fingerprint); err != nil || ok {
		if err != nil {
			return resource.Accepted[resource.Volume]{}, err
		}
		acc, _ := hit.(resource.Accepted[resource.Volume])
		return acc, nil
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
	if hit, ok, err := c.w.begin(m.Key, m.Fingerprint); err != nil || ok {
		if err != nil {
			return resource.Accepted[resource.Volume]{}, err
		}
		acc, _ := hit.(resource.Accepted[resource.Volume])
		return acc, nil
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
		return resource.Accepted[resource.Volume]{}, resource.Conflict(resource.KindVolume, vol.ID.String(), "volume is not available")
	}
	if inst.State != resource.InstanceRunning && inst.State != resource.InstanceStopped {
		return resource.Accepted[resource.Volume]{}, resource.Conflict(resource.KindInstance, inst.ID.String(), "instance cannot accept a volume from "+inst.State.String())
	}
	prev := *vol
	vol.State = resource.VolumeInUse
	vol.InstanceID = req.InstanceID
	vol.Device = req.Device
	op, err := c.w.newOp(m.Account, resource.ServiceCompute, resource.ActionAttachVolume, []resource.Ref{vol.ID.Ref()}, func(time.Time) {})
	if err != nil {
		*vol = prev
		return resource.Accepted[resource.Volume]{}, err
	}
	item := *vol
	acc := resource.Accepted[resource.Volume]{Operation: op, Items: []resource.Volume{item}}
	c.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (c compute) DeleteVolume(ctx context.Context, m backend.Mutation, req resource.DeleteVolumeRequest) (resource.Accepted[resource.Volume], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if hit, ok, err := c.w.begin(m.Key, m.Fingerprint); err != nil || ok {
		if err != nil {
			return resource.Accepted[resource.Volume]{}, err
		}
		acc, _ := hit.(resource.Accepted[resource.Volume])
		return acc, nil
	}
	vol, ok := c.w.vol[req.ID]
	if !ok || vol.OwnerID != m.Account {
		return resource.Accepted[resource.Volume]{}, resource.NotFound(resource.KindVolume, req.ID.String())
	}
	if vol.State == resource.VolumeInUse {
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
	if hit, ok, err := c.w.begin(m.Key, m.Fingerprint); err != nil || ok {
		if err != nil {
			return resource.Accepted[resource.KeyPair]{}, err
		}
		acc, _ := hit.(resource.Accepted[resource.KeyPair])
		return acc, nil
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
	material, fingerprint, err := keyMaterial(c.w.entropy)
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, resource.Internal(err)
	}
	key := resource.KeyPair{
		ID: id, OwnerID: m.Account, Name: req.Name, Fingerprint: fingerprint, Material: material,
	}
	op, err := c.w.newOp(m.Account, resource.ServiceCompute, resource.ActionCreateKeyPair, []resource.Ref{id.Ref()}, func(time.Time) {})
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	stored := key
	stored.Material = ""
	c.w.key[id] = &stored
	acc := resource.Accepted[resource.KeyPair]{Operation: op, Items: []resource.KeyPair{key}}
	c.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (n network) CreateVpc(ctx context.Context, m backend.Mutation, req resource.CreateVpcRequest) (resource.Accepted[resource.Vpc], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	if hit, ok, err := n.w.begin(m.Key, m.Fingerprint); err != nil || ok {
		if err != nil {
			return resource.Accepted[resource.Vpc]{}, err
		}
		acc, _ := hit.(resource.Accepted[resource.Vpc])
		return acc, nil
	}
	id, err := resource.Mint[resource.VpcID](n.w.entropy)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	if _, exists := n.w.vpc[id]; exists {
		return resource.Accepted[resource.Vpc]{}, resource.Internal(errors.New("identifier collision"))
	}
	vpc := resource.Vpc{ID: id, OwnerID: m.Account, Cidr: req.Cidr, State: resource.VpcPending}
	op, err := n.w.newOp(m.Account, resource.ServiceNetwork, resource.ActionCreateVpc, []resource.Ref{id.Ref()}, func(time.Time) {
		if cur := n.w.vpc[id]; cur != nil && cur.State == resource.VpcPending {
			cur.State = resource.VpcAvailable
		}
	})
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	stored := vpc
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
	if hit, ok, err := n.w.begin(m.Key, m.Fingerprint); err != nil || ok {
		if err != nil {
			return resource.Accepted[resource.Vpc]{}, err
		}
		acc, _ := hit.(resource.Accepted[resource.Vpc])
		return acc, nil
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
	if hit, ok, err := n.w.begin(m.Key, m.Fingerprint); err != nil || ok {
		if err != nil {
			return resource.Accepted[resource.SecurityGroup]{}, err
		}
		acc, _ := hit.(resource.Accepted[resource.SecurityGroup])
		return acc, nil
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
	if hit, ok, err := n.w.begin(m.Key, m.Fingerprint); err != nil || ok {
		if err != nil {
			return resource.Accepted[resource.SecurityGroup]{}, err
		}
		acc, _ := hit.(resource.Accepted[resource.SecurityGroup])
		return acc, nil
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

func keyMaterial(entropy io.Reader) (string, string, error) {
	_, priv, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return "", "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", "", errors.New("ed25519 public key")
	}
	sum := sha256.Sum256(pub)
	return string(block), hex.EncodeToString(sum[:]), nil
}
