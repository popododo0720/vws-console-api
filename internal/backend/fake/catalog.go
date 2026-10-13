package fake

import (
	"context"
	"errors"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (c compute) DeleteKeyPair(ctx context.Context, m backend.Mutation, req resource.DeleteKeyPairRequest) (resource.Accepted[resource.KeyPair], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.KeyPair]](c.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	key, err := c.w.findKey(m.Account, req)
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	id := key.ID
	op, err := c.w.newOp(m.Account, resource.ServiceCompute, resource.ActionDeleteKeyPair, []resource.Ref{id.Ref()}, func(time.Time) {
		delete(c.w.key, id)
	})
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	item := *key
	item.Material = ""
	acc := resource.Accepted[resource.KeyPair]{Operation: op, Items: []resource.KeyPair{item}}
	c.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (c compute) DescribeKeyPairs(ctx context.Context, s backend.Scope, q resource.KeyPairQuery) (resource.Page[resource.KeyPair], error) {
	if err := ctx.Err(); err != nil {
		return resource.Page[resource.KeyPair]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	var items []resource.KeyPair
	for _, key := range c.w.key {
		if key.OwnerID != s.Account || !keySelected(*key, q) {
			continue
		}
		item := *key
		item.Material = ""
		items = append(items, item)
	}
	sortOwned(items)
	if len(items) == 0 && (len(q.IDs) == 1 || len(q.Names) == 1) {
		missing := ""
		if len(q.Names) == 1 {
			missing = q.Names[0]
		}
		if len(q.IDs) == 1 {
			missing = q.IDs[0].String()
		}
		return resource.Page[resource.KeyPair]{}, resource.NotFound(resource.KindKeyPair, missing)
	}
	return page(items, q.Page)
}

func (c compute) CreateSnapshot(ctx context.Context, m backend.Mutation, req resource.CreateSnapshotRequest) (resource.Accepted[resource.Snapshot], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Snapshot]](c.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	vol, ok := c.w.vol[req.VolumeID]
	if !ok || vol.OwnerID != m.Account {
		return resource.Accepted[resource.Snapshot]{}, resource.NotFound(resource.KindVolume, req.VolumeID.String())
	}
	if vol.State == resource.VolumeDeleting {
		return resource.Accepted[resource.Snapshot]{}, resource.Conflict(resource.KindVolume, vol.ID.String(), "volume is deleting")
	}
	id, err := resource.Mint[resource.SnapshotID](c.w.entropy)
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	if _, exists := c.w.snap[id]; exists {
		return resource.Accepted[resource.Snapshot]{}, resource.Internal(errors.New("identifier collision"))
	}
	snap := resource.Snapshot{
		ID: id, OwnerID: m.Account, VolumeID: req.VolumeID, VolumeSize: vol.SizeGiB,
		State: resource.SnapshotPending, Description: req.Description,
	}
	op, err := c.w.newOp(m.Account, resource.ServiceCompute, resource.ActionCreateSnapshot, []resource.Ref{id.Ref()}, func(time.Time) {
		if cur := c.w.snap[id]; cur != nil && cur.State == resource.SnapshotPending {
			cur.State = resource.SnapshotCompleted
		}
	})
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	stored := snap
	c.w.snap[id] = &stored
	acc := resource.Accepted[resource.Snapshot]{Operation: op, Items: []resource.Snapshot{snap}}
	c.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (c compute) DeleteSnapshot(ctx context.Context, m backend.Mutation, req resource.DeleteSnapshotRequest) (resource.Accepted[resource.Snapshot], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Snapshot]](c.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	snap, ok := c.w.snap[req.ID]
	if !ok || snap.OwnerID != m.Account {
		return resource.Accepted[resource.Snapshot]{}, resource.NotFound(resource.KindSnapshot, req.ID.String())
	}
	id := snap.ID
	op, err := c.w.newOp(m.Account, resource.ServiceCompute, resource.ActionDeleteSnapshot, []resource.Ref{id.Ref()}, func(time.Time) {
		delete(c.w.snap, id)
	})
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	item := *snap
	acc := resource.Accepted[resource.Snapshot]{Operation: op, Items: []resource.Snapshot{item}}
	c.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (c compute) DescribeSnapshots(ctx context.Context, s backend.Scope, q resource.SnapshotQuery) (resource.Page[resource.Snapshot], error) {
	if err := ctx.Err(); err != nil {
		return resource.Page[resource.Snapshot]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	return pageOwned(c.w.snap, s.Account, q.IDs, q.Page, resource.KindSnapshot)
}

func (n network) DeleteSubnet(ctx context.Context, m backend.Mutation, req resource.DeleteSubnetRequest) (resource.Accepted[resource.Subnet], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Subnet]](n.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	sub, ok := n.w.sub[req.ID]
	if !ok || sub.OwnerID != m.Account {
		return resource.Accepted[resource.Subnet]{}, resource.NotFound(resource.KindSubnet, req.ID.String())
	}
	for _, inst := range n.w.inst {
		if inst.SubnetID == req.ID && inst.State != resource.InstanceTerminated {
			return resource.Accepted[resource.Subnet]{}, resource.Conflict(resource.KindSubnet, req.ID.String(), "subnet has dependents")
		}
	}
	id := sub.ID
	sub.State = resource.SubnetDeleting
	op, err := n.w.newOp(m.Account, resource.ServiceNetwork, resource.ActionDeleteSubnet, []resource.Ref{id.Ref()}, func(time.Time) {
		delete(n.w.sub, id)
	})
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	item := *sub
	acc := resource.Accepted[resource.Subnet]{Operation: op, Items: []resource.Subnet{item}}
	n.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (n network) DeleteSecurityGroup(ctx context.Context, m backend.Mutation, req resource.DeleteSecurityGroupRequest) (resource.Accepted[resource.SecurityGroup], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.SecurityGroup]](n.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	group, err := n.w.findGroup(m.Account, req)
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	id := group.ID
	op, err := n.w.newOp(m.Account, resource.ServiceNetwork, resource.ActionDeleteSecurityGroup, []resource.Ref{id.Ref()}, func(time.Time) {
		delete(n.w.sg, id)
	})
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	item := *group
	acc := resource.Accepted[resource.SecurityGroup]{Operation: op, Items: []resource.SecurityGroup{item}}
	n.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (n network) DescribeSecurityGroups(ctx context.Context, s backend.Scope, q resource.SecurityGroupQuery) (resource.Page[resource.SecurityGroup], error) {
	if err := ctx.Err(); err != nil {
		return resource.Page[resource.SecurityGroup]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	var items []resource.SecurityGroup
	for _, group := range n.w.sg {
		if group.OwnerID != s.Account || !groupSelected(*group, q) {
			continue
		}
		items = append(items, *group)
	}
	sortOwned(items)
	if len(items) == 0 && (len(q.IDs) == 1 || len(q.Names) == 1) {
		missing := ""
		if len(q.Names) == 1 {
			missing = q.Names[0]
		}
		if len(q.IDs) == 1 {
			missing = q.IDs[0].String()
		}
		return resource.Page[resource.SecurityGroup]{}, resource.NotFound(resource.KindSecurityGroup, missing)
	}
	return page(items, q.Page)
}

func (n network) AllocateAddress(ctx context.Context, m backend.Mutation, req resource.AllocateAddressRequest) (resource.Accepted[resource.Address], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Address]](n.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	id, err := resource.Mint[resource.AddressID](n.w.entropy)
	if err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	if _, exists := n.w.addr[id]; exists {
		return resource.Accepted[resource.Address]{}, resource.Internal(errors.New("identifier collision"))
	}
	addr := resource.Address{ID: id, OwnerID: m.Account, PublicIP: n.w.nextPublicIP(), Domain: req.Domain}
	op, err := n.w.newOp(m.Account, resource.ServiceNetwork, resource.ActionAllocateAddress, []resource.Ref{id.Ref()}, func(time.Time) {})
	if err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	stored := addr
	n.w.addr[id] = &stored
	acc := resource.Accepted[resource.Address]{Operation: op, Items: []resource.Address{addr}}
	n.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (n network) ReleaseAddress(ctx context.Context, m backend.Mutation, req resource.ReleaseAddressRequest) (resource.Accepted[resource.Address], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Address]](n.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	addr, ok := n.w.addr[req.ID]
	if !ok || addr.OwnerID != m.Account {
		return resource.Accepted[resource.Address]{}, resource.NotFound(resource.KindAddress, req.ID.String())
	}
	id := addr.ID
	op, err := n.w.newOp(m.Account, resource.ServiceNetwork, resource.ActionReleaseAddress, []resource.Ref{id.Ref()}, func(time.Time) {
		delete(n.w.addr, id)
	})
	if err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	item := *addr
	acc := resource.Accepted[resource.Address]{Operation: op, Items: []resource.Address{item}}
	n.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (n network) DescribeAddresses(ctx context.Context, s backend.Scope, q resource.AddressQuery) (resource.Page[resource.Address], error) {
	if err := ctx.Err(); err != nil {
		return resource.Page[resource.Address]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	var items []resource.Address
	for _, addr := range n.w.addr {
		if addr.OwnerID != s.Account || !addressSelected(*addr, q) {
			continue
		}
		items = append(items, *addr)
	}
	sortOwned(items)
	if len(items) == 0 && (len(q.IDs) == 1 || len(q.PublicIPs) == 1) {
		missing := ""
		if len(q.PublicIPs) == 1 {
			missing = q.PublicIPs[0]
		}
		if len(q.IDs) == 1 {
			missing = q.IDs[0].String()
		}
		return resource.Page[resource.Address]{}, resource.NotFound(resource.KindAddress, missing)
	}
	return page(items, q.Page)
}

func (w *World) findKey(account resource.AccountID, req resource.DeleteKeyPairRequest) (*resource.KeyPair, error) {
	if !req.ID.IsZero() {
		key, ok := w.key[req.ID]
		if !ok || key.OwnerID != account || (req.Name != "" && key.Name != req.Name) {
			return nil, resource.NotFound(resource.KindKeyPair, req.ID.String())
		}
		return key, nil
	}
	for _, key := range w.key {
		if key.OwnerID == account && key.Name == req.Name {
			return key, nil
		}
	}
	return nil, resource.NotFound(resource.KindKeyPair, req.Name)
}

func (w *World) findGroup(account resource.AccountID, req resource.DeleteSecurityGroupRequest) (*resource.SecurityGroup, error) {
	if !req.ID.IsZero() {
		group, ok := w.sg[req.ID]
		if !ok || group.OwnerID != account || (req.Name != "" && group.Name != req.Name) {
			return nil, resource.NotFound(resource.KindSecurityGroup, req.ID.String())
		}
		return group, nil
	}
	var found *resource.SecurityGroup
	for _, group := range w.sg {
		if group.OwnerID == account && group.Name == req.Name {
			if found != nil {
				return nil, resource.Invalid("groupName", "matches more than one group")
			}
			found = group
		}
	}
	if found == nil {
		return nil, resource.NotFound(resource.KindSecurityGroup, req.Name)
	}
	return found, nil
}

func (w *World) nextPublicIP() string {
	w.seqIP++
	n := w.seqIP
	return "203.0.113." + itoa(int(n%250+1))
}

func keySelected(key resource.KeyPair, q resource.KeyPairQuery) bool {
	if len(q.IDs) > 0 && !containsID(q.IDs, key.ID) {
		return false
	}
	if len(q.Names) > 0 && !containsString(q.Names, key.Name) {
		return false
	}
	return true
}

func groupSelected(group resource.SecurityGroup, q resource.SecurityGroupQuery) bool {
	if len(q.IDs) > 0 && !containsID(q.IDs, group.ID) {
		return false
	}
	if len(q.Names) > 0 && !containsString(q.Names, group.Name) {
		return false
	}
	return true
}

func addressSelected(addr resource.Address, q resource.AddressQuery) bool {
	if len(q.IDs) > 0 && !containsID(q.IDs, addr.ID) {
		return false
	}
	if len(q.PublicIPs) > 0 && !containsString(q.PublicIPs, addr.PublicIP) {
		return false
	}
	return true
}

func containsID[T interface{ String() string }](ids []T, id T) bool {
	for _, item := range ids {
		if item.String() == id.String() {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// AssociateAddress attaches an address to an instance. Like the network
// service, one instance holds at most one address.
func (n network) AssociateAddress(ctx context.Context, m backend.Mutation, req resource.AssociateAddressRequest) (resource.Accepted[resource.Address], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Address]](n.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	addr, ok := n.w.addr[req.ID]
	if !ok || addr.OwnerID != m.Account {
		return resource.Accepted[resource.Address]{}, resource.NotFound(resource.KindAddress, req.ID.String())
	}
	inst, ok := n.w.inst[req.InstanceID]
	if !ok || inst.OwnerID != m.Account || inst.State == resource.InstanceTerminated {
		return resource.Accepted[resource.Address]{}, resource.NotFound(resource.KindInstance, req.InstanceID.String())
	}
	for _, other := range n.w.addr {
		if other.ID != addr.ID && other.InstanceID == req.InstanceID {
			return resource.Accepted[resource.Address]{}, resource.Invalid("instanceId", "instance already has an address")
		}
	}
	return n.setAssociation(m, addr, req.InstanceID, resource.ActionAssociateAddress)
}

// DisassociateAddress detaches an address. An unknown or idle address has no
// association to remove.
func (n network) DisassociateAddress(ctx context.Context, m backend.Mutation, req resource.DisassociateAddressRequest) (resource.Accepted[resource.Address], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Address]](n.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	addr, ok := n.w.addr[req.ID]
	if !ok || addr.OwnerID != m.Account || addr.InstanceID.IsZero() {
		return resource.Accepted[resource.Address]{}, resource.AssociationNotFound(req.ID)
	}
	return n.setAssociation(m, addr, resource.InstanceID{}, resource.ActionDisassociateAddress)
}

func (n network) setAssociation(m backend.Mutation, addr *resource.Address, inst resource.InstanceID, action resource.Action) (resource.Accepted[resource.Address], error) {
	op, err := n.w.newOp(m.Account, resource.ServiceNetwork, action, []resource.Ref{addr.ID.Ref()}, func(time.Time) {})
	if err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	addr.InstanceID = inst
	acc := resource.Accepted[resource.Address]{Operation: op, Items: []resource.Address{*addr}}
	n.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}
