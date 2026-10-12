package grpcclient

import (
	"context"
	"errors"

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (c computeClient) DeleteKeyPair(ctx context.Context, m backend.Mutation, req resource.DeleteKeyPairRequest) (resource.Accepted[resource.KeyPair], error) {
	projectID := project(m.Account)
	key, getErr := c.lookupKey(ctx, projectID, req)
	if getErr != nil && (!missingResource(getErr) || req.ID.IsZero()) {
		return resource.Accepted[resource.KeyPair]{}, getErr
	}
	id := req.ID.String()
	if getErr == nil {
		id = key.ID.String()
	}
	deleted, err := c.keys.DeleteKeyPair(ctx, &computev1.DeleteKeyPairRequest{
		Name:      keyPairName(projectID, id),
		RequestId: requestUUID(m.Key, "delete-key"),
	})
	if rpc := rpcErr(deleted, err); rpc != nil {
		if getErr != nil && missingResource(rpc) {
			return resource.Accepted[resource.KeyPair]{}, getErr
		}
		return resource.Accepted[resource.KeyPair]{}, rpc
	}
	op, err := operationFrom(deleted, resource.ServiceCompute)
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	if getErr != nil {
		parsed, err := resource.Parse[resource.KeyPairID](id)
		if err != nil {
			return resource.Accepted[resource.KeyPair]{}, resource.Internal(err)
		}
		key = resource.KeyPair{ID: parsed, OwnerID: op.OwnerID}
	}
	key.Material = ""
	op.Action = resource.ActionDeleteKeyPair
	op.Targets = []resource.Ref{key.ID.Ref()}
	return resource.Accepted[resource.KeyPair]{Operation: op, Items: []resource.KeyPair{key}}, nil
}

func (c computeClient) DescribeKeyPairs(ctx context.Context, s backend.Scope, q resource.KeyPairQuery) (resource.Page[resource.KeyPair], error) {
	projectID := project(s.Account)
	if len(q.IDs) == 1 && len(q.Names) == 0 {
		key, err := c.getKey(ctx, projectID, q.IDs[0].String())
		if err != nil {
			return resource.Page[resource.KeyPair]{}, err
		}
		return pageByID([]resource.KeyPair{key}, q.Page, func(item resource.KeyPair) string { return item.ID.String() })
	}
	items, err := c.listKeys(ctx, projectID)
	if err != nil {
		return resource.Page[resource.KeyPair]{}, err
	}
	filtered := items[:0]
	for _, key := range items {
		if !keyVisible(key, q) {
			continue
		}
		filtered = append(filtered, key)
	}
	if len(filtered) == 0 && (len(q.IDs) == 1 || len(q.Names) == 1) {
		missing := ""
		if len(q.Names) == 1 {
			missing = q.Names[0]
		}
		if len(q.IDs) == 1 {
			missing = q.IDs[0].String()
		}
		return resource.Page[resource.KeyPair]{}, resource.NotFound(resource.KindKeyPair, missing)
	}
	return pageByID(filtered, q.Page, func(item resource.KeyPair) string { return item.ID.String() })
}

func (c computeClient) CreateSnapshot(ctx context.Context, m backend.Mutation, req resource.CreateSnapshotRequest) (resource.Accepted[resource.Snapshot], error) {
	projectID := project(m.Account)
	vol, err := c.getVolume(ctx, projectID, req.VolumeID.String())
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	created, err := c.snapshots.CreateSnapshot(ctx, &storagev1.CreateSnapshotRequest{
		Parent:     regionParent(projectID),
		SnapshotId: derivedID("snap-", m.Key, "snap"),
		RequestId:  requestUUID(m.Key, "snap"),
		Snapshot: &storagev1.Snapshot{
			Labels: map[string]string{labelFingerprint: clip(m.Fingerprint, 63)},
			Spec: &storagev1.SnapshotSpec{
				Volume:      volumeName(projectID, req.VolumeID.String()),
				Description: req.Description,
			},
		},
	})
	if err := rpcErr(created, err); err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	op, err := operationFrom(created, resource.ServiceCompute)
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	metaName, err := metadataResource(created)
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	id, err := resource.Parse[resource.SnapshotID](lastSegment(metaName))
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, resource.Internal(err)
	}
	owner, err := accountIn(metaName)
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	snap := resource.Snapshot{
		ID: id, OwnerID: owner, VolumeID: req.VolumeID, VolumeSize: vol.SizeGiB,
		State: resource.SnapshotPending, Description: req.Description,
	}
	op.Action = resource.ActionCreateSnapshot
	op.Targets = []resource.Ref{id.Ref()}
	return resource.Accepted[resource.Snapshot]{Operation: op, Items: []resource.Snapshot{snap}}, nil
}

func (c computeClient) DeleteSnapshot(ctx context.Context, m backend.Mutation, req resource.DeleteSnapshotRequest) (resource.Accepted[resource.Snapshot], error) {
	projectID := project(m.Account)
	snap, getErr := c.getSnapshot(ctx, projectID, req.ID.String())
	if getErr != nil && !missingResource(getErr) {
		return resource.Accepted[resource.Snapshot]{}, getErr
	}
	deleted, err := c.snapshots.DeleteSnapshot(ctx, &storagev1.DeleteSnapshotRequest{
		Name:      snapshotName(projectID, req.ID.String()),
		RequestId: requestUUID(m.Key, "delete-snap"),
	})
	if rpc := rpcErr(deleted, err); rpc != nil {
		if getErr != nil && missingResource(rpc) {
			return resource.Accepted[resource.Snapshot]{}, getErr
		}
		return resource.Accepted[resource.Snapshot]{}, rpc
	}
	op, err := operationFrom(deleted, resource.ServiceCompute)
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	if getErr != nil {
		snap = resource.Snapshot{ID: req.ID, OwnerID: op.OwnerID}
	}
	op.Action = resource.ActionDeleteSnapshot
	op.Targets = []resource.Ref{snap.ID.Ref()}
	return resource.Accepted[resource.Snapshot]{Operation: op, Items: []resource.Snapshot{snap}}, nil
}

func (c computeClient) DescribeSnapshots(ctx context.Context, s backend.Scope, q resource.SnapshotQuery) (resource.Page[resource.Snapshot], error) {
	projectID := project(s.Account)
	if len(q.IDs) == 1 {
		snap, err := c.getSnapshot(ctx, projectID, q.IDs[0].String())
		if err != nil {
			return resource.Page[resource.Snapshot]{}, err
		}
		return pageByID([]resource.Snapshot{snap}, q.Page, func(item resource.Snapshot) string { return item.ID.String() })
	}
	want := map[string]struct{}{}
	for _, id := range q.IDs {
		want[id.String()] = struct{}{}
	}
	var items []resource.Snapshot
	token := ""
	for page := 0; page < 50; page++ {
		out, err := c.snapshots.ListSnapshots(ctx, &storagev1.ListSnapshotsRequest{
			Parent: regionParent(projectID), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return resource.Page[resource.Snapshot]{}, fromRPC(err)
		}
		for _, item := range out.GetSnapshots() {
			snap, err := snapshotModel(item)
			if err != nil {
				return resource.Page[resource.Snapshot]{}, err
			}
			if len(want) > 0 {
				if _, ok := want[snap.ID.String()]; !ok {
					continue
				}
			}
			items = append(items, snap)
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	if len(q.IDs) == 1 && len(items) == 0 {
		return resource.Page[resource.Snapshot]{}, resource.NotFound(resource.KindSnapshot, q.IDs[0].String())
	}
	return pageByID(items, q.Page, func(item resource.Snapshot) string { return item.ID.String() })
}

func (c networkClient) DeleteSubnet(ctx context.Context, m backend.Mutation, req resource.DeleteSubnetRequest) (resource.Accepted[resource.Subnet], error) {
	// The subnet name includes the VPC. After the row is gone the client cannot form it.
	projectID := project(m.Account)
	name, err := computeClient(c).findSubnet(ctx, projectID, req.ID.String())
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	current, err := c.subnets.GetSubnet(ctx, &networkv1.GetSubnetRequest{Name: name})
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, fromRPC(err)
	}
	sub, err := subnetModel(current)
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	deleted, err := c.subnets.DeleteSubnet(ctx, &networkv1.DeleteSubnetRequest{
		Name:      name,
		RequestId: requestUUID(m.Key, "delete-subnet"),
	})
	if err := rpcErr(deleted, err); err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	op, err := operationFrom(deleted, resource.ServiceNetwork)
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	op.Action = resource.ActionDeleteSubnet
	op.Targets = []resource.Ref{sub.ID.Ref()}
	return resource.Accepted[resource.Subnet]{Operation: op, Items: []resource.Subnet{sub}}, nil
}

func (c networkClient) DeleteSecurityGroup(ctx context.Context, m backend.Mutation, req resource.DeleteSecurityGroupRequest) (resource.Accepted[resource.SecurityGroup], error) {
	// The group name includes the VPC. After the row is gone the client cannot form it.
	projectID := project(m.Account)
	group, err := c.findGroupRequest(ctx, projectID, req)
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	deleted, err := c.groups.DeleteSecurityGroup(ctx, &networkv1.DeleteSecurityGroupRequest{
		Name:      securityGroupName(projectID, group.VpcID.String(), group.ID.String()),
		RequestId: requestUUID(m.Key, "delete-sg"),
	})
	if err := rpcErr(deleted, err); err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	op, err := operationFrom(deleted, resource.ServiceNetwork)
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	op.Action = resource.ActionDeleteSecurityGroup
	op.Targets = []resource.Ref{group.ID.Ref()}
	return resource.Accepted[resource.SecurityGroup]{Operation: op, Items: []resource.SecurityGroup{group}}, nil
}

func (c networkClient) DescribeSecurityGroups(ctx context.Context, s backend.Scope, q resource.SecurityGroupQuery) (resource.Page[resource.SecurityGroup], error) {
	projectID := project(s.Account)
	items, err := c.listGroups(ctx, projectID)
	if err != nil {
		return resource.Page[resource.SecurityGroup]{}, err
	}
	filtered := items[:0]
	for _, group := range items {
		if !groupVisible(group, q) {
			continue
		}
		filtered = append(filtered, group)
	}
	if len(filtered) == 0 && (len(q.IDs) == 1 || len(q.Names) == 1) {
		missing := ""
		if len(q.Names) == 1 {
			missing = q.Names[0]
		}
		if len(q.IDs) == 1 {
			missing = q.IDs[0].String()
		}
		return resource.Page[resource.SecurityGroup]{}, resource.NotFound(resource.KindSecurityGroup, missing)
	}
	return pageByID(filtered, q.Page, func(item resource.SecurityGroup) string { return item.ID.String() })
}

// defaultVPCCIDR is the account network created for AllocateAddress when the
// project has none. The address proto has no VPC field. EC2 AllocateAddress
// defaults to Domain=vpc and does not take a VPC id, and the network service
// rejects an address in a project that has no VPC.
const defaultVPCCIDR = "172.31.0.0/16"

func (c networkClient) AllocateAddress(ctx context.Context, m backend.Mutation, req resource.AllocateAddressRequest) (resource.Accepted[resource.Address], error) {
	projectID := project(m.Account)
	vpc, err := c.ensureVPC(ctx, projectID)
	if err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	created, err := c.addresses.CreateAddress(ctx, &networkv1.CreateAddressRequest{
		Parent:    regionParent(projectID),
		AddressId: derivedID("eipalloc-", m.Key, "addr"),
		RequestId: requestUUID(m.Key, "addr"),
		Address: &networkv1.Address{
			Labels: map[string]string{labelFingerprint: clip(m.Fingerprint, 63)},
			Spec:   &networkv1.AddressSpec{IpVersion: networkv1.IpVersion_IP_VERSION_IPV4, Vpc: vpc},
		},
	})
	if err := rpcErr(created, err); err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	op, err := operationFrom(created, resource.ServiceNetwork)
	if err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	metaName, err := metadataResource(created)
	if err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	id, err := resource.Parse[resource.AddressID](lastSegment(metaName))
	if err != nil {
		return resource.Accepted[resource.Address]{}, resource.Internal(err)
	}
	owner, err := accountIn(metaName)
	if err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	addr := resource.Address{ID: id, OwnerID: owner, Domain: req.Domain}
	if got, getErr := c.getAddress(ctx, projectID, id.String()); getErr == nil {
		addr.PublicIP = got.PublicIP
		addr.InstanceID = got.InstanceID
	}
	op.Action = resource.ActionAllocateAddress
	op.Targets = []resource.Ref{id.Ref()}
	return resource.Accepted[resource.Address]{Operation: op, Items: []resource.Address{addr}}, nil
}

// ensureVPC returns the VPC an address is allocated in. The network service
// requires spec.vpc and the binding is immutable. The oldest VPC of the project
// wins: sorted by create time, then by name. The choice does not depend on the
// order ListVpcs returns. The address can later attach to an instance in that
// VPC only. A project with no VPC gets the default one.
func (c networkClient) ensureVPC(ctx context.Context, projectID string) (string, error) {
	var first *networkv1.Vpc
	token := ""
	for page := 0; page < 20; page++ {
		out, err := c.vpcs.ListVpcs(ctx, &networkv1.ListVpcsRequest{
			Parent: regionParent(projectID), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return "", fromRPC(err)
		}
		for _, vpc := range out.GetVpcs() {
			if first == nil || vpcBefore(vpc, first) {
				first = vpc
			}
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	if first != nil {
		return first.GetName(), nil
	}
	id := derivedID("vpc-", projectID, "default")
	created, err := c.vpcs.CreateVpc(ctx, &networkv1.CreateVpcRequest{
		Parent:    regionParent(projectID),
		VpcId:     id,
		RequestId: requestUUID(projectID, "default-vpc"),
		Vpc:       &networkv1.Vpc{Spec: &networkv1.VpcSpec{Ipv4Cidr: defaultVPCCIDR}},
	})
	if err := rpcErr(created, err); err != nil && resource.CodeOf(err) != resource.CodeAlreadyExists {
		return "", err
	}
	return vpcName(projectID, id), nil
}

// vpcBefore orders VPCs by create time, then by name.
func vpcBefore(a, b *networkv1.Vpc) bool {
	if at, bt := a.GetCreateTime().AsTime(), b.GetCreateTime().AsTime(); !at.Equal(bt) {
		return at.Before(bt)
	}
	return a.GetName() < b.GetName()
}

func (c networkClient) ReleaseAddress(ctx context.Context, m backend.Mutation, req resource.ReleaseAddressRequest) (resource.Accepted[resource.Address], error) {
	projectID := project(m.Account)
	addr, getErr := c.getAddress(ctx, projectID, req.ID.String())
	if getErr != nil && !missingResource(getErr) {
		return resource.Accepted[resource.Address]{}, getErr
	}
	deleted, err := c.addresses.DeleteAddress(ctx, &networkv1.DeleteAddressRequest{
		Name:      addressName(projectID, req.ID.String()),
		RequestId: requestUUID(m.Key, "release-addr"),
	})
	if rpc := rpcErr(deleted, err); rpc != nil {
		if getErr != nil && missingResource(rpc) {
			return resource.Accepted[resource.Address]{}, getErr
		}
		return resource.Accepted[resource.Address]{}, rpc
	}
	op, err := operationFrom(deleted, resource.ServiceNetwork)
	if err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	if getErr != nil {
		addr = resource.Address{ID: req.ID, OwnerID: op.OwnerID}
	}
	op.Action = resource.ActionReleaseAddress
	op.Targets = []resource.Ref{addr.ID.Ref()}
	return resource.Accepted[resource.Address]{Operation: op, Items: []resource.Address{addr}}, nil
}

func (c networkClient) DescribeAddresses(ctx context.Context, s backend.Scope, q resource.AddressQuery) (resource.Page[resource.Address], error) {
	projectID := project(s.Account)
	if len(q.IDs) == 1 && len(q.PublicIPs) == 0 {
		addr, err := c.getAddress(ctx, projectID, q.IDs[0].String())
		if err != nil {
			return resource.Page[resource.Address]{}, err
		}
		return pageByID([]resource.Address{addr}, q.Page, func(item resource.Address) string { return item.ID.String() })
	}
	var items []resource.Address
	token := ""
	for page := 0; page < 50; page++ {
		out, err := c.addresses.ListAddresses(ctx, &networkv1.ListAddressesRequest{
			Parent: regionParent(projectID), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return resource.Page[resource.Address]{}, fromRPC(err)
		}
		for _, item := range out.GetAddresses() {
			addr, err := addressModel(item)
			if err != nil {
				return resource.Page[resource.Address]{}, err
			}
			if !addressVisible(addr, q) {
				continue
			}
			items = append(items, addr)
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
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
	return pageByID(items, q.Page, func(item resource.Address) string { return item.ID.String() })
}

func missingResource(err error) bool {
	return resource.CodeOf(err) == resource.CodeNotFound
}

func (c computeClient) lookupKey(ctx context.Context, projectID string, req resource.DeleteKeyPairRequest) (resource.KeyPair, error) {
	if req.ID.IsZero() {
		return c.findKey(ctx, projectID, req)
	}
	key, err := c.getKey(ctx, projectID, req.ID.String())
	if err != nil {
		return resource.KeyPair{}, err
	}
	if req.Name != "" && key.Name != req.Name {
		return resource.KeyPair{}, resource.NotFound(resource.KindKeyPair, req.ID.String())
	}
	return key, nil
}

func (c computeClient) findKey(ctx context.Context, projectID string, req resource.DeleteKeyPairRequest) (resource.KeyPair, error) {
	items, err := c.listKeys(ctx, projectID)
	if err != nil {
		return resource.KeyPair{}, err
	}
	for _, key := range items {
		if key.Name == req.Name {
			return key, nil
		}
	}
	return resource.KeyPair{}, resource.NotFound(resource.KindKeyPair, req.Name)
}

func (c computeClient) getKey(ctx context.Context, projectID, id string) (resource.KeyPair, error) {
	out, err := c.keys.GetKeyPair(ctx, &computev1.GetKeyPairRequest{Name: keyPairName(projectID, id)})
	if err != nil {
		return resource.KeyPair{}, fromRPC(err)
	}
	return keyModel(out)
}

func (c computeClient) listKeys(ctx context.Context, projectID string) ([]resource.KeyPair, error) {
	var items []resource.KeyPair
	token := ""
	for page := 0; page < 50; page++ {
		out, err := c.keys.ListKeyPairs(ctx, &computev1.ListKeyPairsRequest{
			Parent: regionParent(projectID), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return nil, fromRPC(err)
		}
		for _, item := range out.GetKeyPairs() {
			key, err := keyModel(item)
			if err != nil {
				return nil, err
			}
			items = append(items, key)
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return items, nil
}

func (c computeClient) getSnapshot(ctx context.Context, projectID, id string) (resource.Snapshot, error) {
	out, err := c.snapshots.GetSnapshot(ctx, &storagev1.GetSnapshotRequest{Name: snapshotName(projectID, id)})
	if err != nil {
		return resource.Snapshot{}, fromRPC(err)
	}
	return snapshotModel(out)
}

func (c networkClient) getAddress(ctx context.Context, projectID, id string) (resource.Address, error) {
	out, err := c.addresses.GetAddress(ctx, &networkv1.GetAddressRequest{Name: addressName(projectID, id)})
	if err != nil {
		return resource.Address{}, fromRPC(err)
	}
	return addressModel(out)
}

func (c networkClient) findGroupRequest(ctx context.Context, projectID string, req resource.DeleteSecurityGroupRequest) (resource.SecurityGroup, error) {
	if !req.ID.IsZero() {
		group, err := c.findGroup(ctx, projectID, req.ID.String())
		if err != nil {
			return resource.SecurityGroup{}, err
		}
		if req.Name != "" && group.Name != req.Name {
			return resource.SecurityGroup{}, resource.NotFound(resource.KindSecurityGroup, req.ID.String())
		}
		return group, nil
	}
	items, err := c.listGroups(ctx, projectID)
	if err != nil {
		return resource.SecurityGroup{}, err
	}
	var found resource.SecurityGroup
	var matches int
	for _, group := range items {
		if group.Name == req.Name {
			found = group
			matches++
		}
	}
	if matches > 1 {
		return resource.SecurityGroup{}, resource.Invalid("groupName", "matches more than one group")
	}
	if matches == 0 {
		return resource.SecurityGroup{}, resource.NotFound(resource.KindSecurityGroup, req.Name)
	}
	return found, nil
}

func (c networkClient) listGroups(ctx context.Context, projectID string) ([]resource.SecurityGroup, error) {
	var items []resource.SecurityGroup
	token := ""
	for page := 0; page < 50; page++ {
		out, err := c.vpcs.ListVpcs(ctx, &networkv1.ListVpcsRequest{
			Parent: regionParent(projectID), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return nil, fromRPC(err)
		}
		for _, vpc := range out.GetVpcs() {
			groupToken := ""
			for groupPage := 0; groupPage < 50; groupPage++ {
				listed, err := c.groups.ListSecurityGroups(ctx, &networkv1.ListSecurityGroupsRequest{
					Parent: vpc.GetName(), PageSize: 100, PageToken: groupToken,
				})
				if err != nil {
					return nil, fromRPC(err)
				}
				for _, item := range listed.GetSecurityGroups() {
					group, err := groupModel(item)
					if err != nil {
						return nil, err
					}
					items = append(items, group)
				}
				groupToken = listed.GetNextPageToken()
				if groupToken == "" {
					break
				}
			}
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return items, nil
}

func keyModel(in *computev1.KeyPair) (resource.KeyPair, error) {
	if in == nil {
		return resource.KeyPair{}, resource.Internal(errors.New("missing key pair"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 6 || parts[4] != "keyPairs" {
		return resource.KeyPair{}, resource.Internal(errors.New("bad key pair name"))
	}
	id, err := resource.Parse[resource.KeyPairID](parts[5])
	if err != nil {
		return resource.KeyPair{}, resource.Internal(err)
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.KeyPair{}, err
	}
	return resource.KeyPair{
		ID: id, OwnerID: owner, Name: labelName(in.GetLabels()), Fingerprint: in.GetStatus().GetFingerprintSha256(),
	}, nil
}

func snapshotModel(in *storagev1.Snapshot) (resource.Snapshot, error) {
	if in == nil {
		return resource.Snapshot{}, resource.Internal(errors.New("missing snapshot"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 6 || parts[4] != "snapshots" {
		return resource.Snapshot{}, resource.Internal(errors.New("bad snapshot name"))
	}
	id, err := resource.Parse[resource.SnapshotID](parts[5])
	if err != nil {
		return resource.Snapshot{}, resource.Internal(err)
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.Snapshot{}, err
	}
	vol, err := resource.Parse[resource.VolumeID](lastSegment(in.GetSpec().GetVolume()))
	if err != nil {
		return resource.Snapshot{}, resource.Internal(err)
	}
	state := resource.SnapshotPending
	if in.GetStatus().GetObserved().GetState() == commonv1.ReconciliationState_RECONCILIATION_STATE_READY {
		state = resource.SnapshotCompleted
	}
	return resource.Snapshot{
		ID: id, OwnerID: owner, VolumeID: vol, VolumeSize: in.GetStatus().GetSizeGib(),
		State: state, Description: in.GetSpec().GetDescription(),
	}, nil
}

func addressModel(in *networkv1.Address) (resource.Address, error) {
	if in == nil {
		return resource.Address{}, resource.Internal(errors.New("missing address"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 6 || parts[4] != "addresses" {
		return resource.Address{}, resource.Internal(errors.New("bad address name"))
	}
	id, err := resource.Parse[resource.AddressID](parts[5])
	if err != nil {
		return resource.Address{}, resource.Internal(err)
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.Address{}, err
	}
	var inst resource.InstanceID
	if name := in.GetStatus().GetInstance(); name != "" {
		parsed, err := resource.Parse[resource.InstanceID](lastSegment(name))
		if err != nil {
			return resource.Address{}, resource.Internal(err)
		}
		inst = parsed
	}
	return resource.Address{
		ID: id, OwnerID: owner, PublicIP: in.GetStatus().GetIpv4(), Domain: "vpc", InstanceID: inst,
	}, nil
}

func keyVisible(key resource.KeyPair, q resource.KeyPairQuery) bool {
	if len(q.IDs) > 0 && !idListed(q.IDs, key.ID) {
		return false
	}
	if len(q.Names) > 0 && !stringListed(q.Names, key.Name) {
		return false
	}
	return true
}

func groupVisible(group resource.SecurityGroup, q resource.SecurityGroupQuery) bool {
	if len(q.IDs) > 0 && !idListed(q.IDs, group.ID) {
		return false
	}
	if len(q.Names) > 0 && !stringListed(q.Names, group.Name) {
		return false
	}
	return true
}

func addressVisible(addr resource.Address, q resource.AddressQuery) bool {
	if len(q.IDs) > 0 && !idListed(q.IDs, addr.ID) {
		return false
	}
	if len(q.PublicIPs) > 0 && !stringListed(q.PublicIPs, addr.PublicIP) {
		return false
	}
	return true
}

func idListed[T interface{ String() string }](ids []T, id T) bool {
	for _, item := range ids {
		if item.String() == id.String() {
			return true
		}
	}
	return false
}

func stringListed(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
