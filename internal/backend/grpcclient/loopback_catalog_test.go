package grpcclient

import (
	"context"
	"errors"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (s *keySrv) GetKeyPair(ctx context.Context, req *computev1.GetKeyPairRequest) (*computev1.KeyPair, error) {
	projectID, account, id, err := keyRef(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	page, err := s.w.set.Compute.DescribeKeyPairs(ctx, backend.Scope{Account: account}, resource.KeyPairQuery{
		IDs: []resource.KeyPairID{id}, Page: resource.PageRequest{Size: 1},
	})
	if err != nil {
		return nil, toStatus(err)
	}
	if len(page.Items) == 0 {
		return nil, toStatus(resource.NotFound(resource.KindKeyPair, id.String()))
	}
	return keyProto(page.Items[0], projectID, s.w.keyLineOf(page.Items[0].ID.String())), nil
}

func (s *keySrv) ListKeyPairs(ctx context.Context, req *computev1.ListKeyPairsRequest) (*computev1.ListKeyPairsResponse, error) {
	projectID, account, err := accountFromParent(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	page, err := s.w.set.Compute.DescribeKeyPairs(ctx, backend.Scope{Account: account}, resource.KeyPairQuery{
		Page: resource.PageRequest{Size: listPageSize(req.GetPageSize()), Token: req.GetPageToken()},
	})
	if err != nil {
		return nil, toStatus(err)
	}
	items := make([]*computev1.KeyPair, 0, len(page.Items))
	for _, key := range page.Items {
		items = append(items, keyProto(key, projectID, s.w.keyLineOf(key.ID.String())))
	}
	return &computev1.ListKeyPairsResponse{KeyPairs: items, NextPageToken: page.NextToken}, nil
}

func (s *keySrv) DeleteKeyPair(ctx context.Context, req *computev1.DeleteKeyPairRequest) (*longrunningpb.Operation, error) {
	projectID, account, id, err := keyRef(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Compute.DeleteKeyPair(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.DeleteKeyPairRequest{ID: id})
	if err != nil {
		return nil, toStatus(err)
	}
	return runningOp(projectID, acc.Operation, keyPairName(projectID, id.String()), commonv1.OperationVerb_OPERATION_VERB_DELETE, s.w.now)
}

func (s *groupSrv) ListSecurityGroups(_ context.Context, req *networkv1.ListSecurityGroupsRequest) (*networkv1.ListSecurityGroupsResponse, error) {
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	if req.GetPageToken() != "" {
		return nil, toStatus(resource.Invalid("pageToken", "unknown"))
	}
	vpcID := lastSegment(req.GetParent())
	items := make([]*networkv1.SecurityGroup, 0)
	for _, group := range s.w.groupsIn(vpcID) {
		items = append(items, groupProto(group, projectID))
	}
	return &networkv1.ListSecurityGroupsResponse{SecurityGroups: items}, nil
}

func (s *groupSrv) DeleteSecurityGroup(ctx context.Context, req *networkv1.DeleteSecurityGroupRequest) (*longrunningpb.Operation, error) {
	projectID, err := projectOfName(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	id, err := resource.Parse[resource.SecurityGroupID](lastSegment(req.GetName()))
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Network.DeleteSecurityGroup(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.DeleteSecurityGroupRequest{ID: id})
	if err != nil {
		return nil, toStatus(err)
	}
	return runningOp(projectID, acc.Operation, req.GetName(), commonv1.OperationVerb_OPERATION_VERB_DELETE, s.w.now)
}

func (s *subnetSrv) DeleteSubnet(ctx context.Context, req *networkv1.DeleteSubnetRequest) (*longrunningpb.Operation, error) {
	projectID, err := projectOfName(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	id, err := resource.Parse[resource.SubnetID](lastSegment(req.GetName()))
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Network.DeleteSubnet(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.DeleteSubnetRequest{ID: id})
	if err != nil {
		return nil, toStatus(err)
	}
	return runningOp(projectID, acc.Operation, req.GetName(), commonv1.OperationVerb_OPERATION_VERB_DELETE, s.w.now)
}

type addressSrv struct {
	networkv1.UnimplementedAddressServiceServer
	w *loopWorld
}

func (s *addressSrv) CreateAddress(ctx context.Context, req *networkv1.CreateAddressRequest) (*longrunningpb.Operation, error) {
	projectID, account, err := accountFromParent(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Network.AllocateAddress(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.AllocateAddressRequest{Domain: "vpc"})
	if err != nil {
		return nil, toStatus(err)
	}
	return runningOp(projectID, acc.Operation, addressName(projectID, acc.Items[0].ID.String()), commonv1.OperationVerb_OPERATION_VERB_CREATE, s.w.now)
}

// UpdateAddress serves only the spec.association mask, the one the client sends.
func (s *addressSrv) UpdateAddress(ctx context.Context, req *networkv1.UpdateAddressRequest) (*longrunningpb.Operation, error) {
	if paths := req.GetUpdateMask().GetPaths(); len(paths) != 1 || paths[0] != "spec.association" {
		return nil, toStatus(resource.Invalid("updateMask", "unsupported"))
	}
	projectID, account, id, err := addressRef(req.GetAddress().GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	m := backend.Mutation{Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp}
	var acc resource.Accepted[resource.Address]
	if assoc := req.GetAddress().GetSpec().GetAssociation(); assoc != nil {
		if assoc.GetDeviceName() != "nic0" {
			return nil, toStatus(resource.Invalid("deviceName", "no such interface"))
		}
		inst, perr := resource.Parse[resource.InstanceID](lastSegment(assoc.GetInstance()))
		if perr != nil {
			return nil, toStatus(perr)
		}
		acc, err = s.w.set.Network.AssociateAddress(ctx, m, resource.AssociateAddressRequest{ID: id, InstanceID: inst})
	} else {
		acc, err = s.w.set.Network.DisassociateAddress(ctx, m, resource.DisassociateAddressRequest{ID: id})
	}
	if err != nil {
		return nil, toStatus(err)
	}
	return runningOp(projectID, acc.Operation, addressName(projectID, id.String()), commonv1.OperationVerb_OPERATION_VERB_UPDATE, s.w.now)
}

func (s *addressSrv) GetAddress(ctx context.Context, req *networkv1.GetAddressRequest) (*networkv1.Address, error) {
	projectID, account, id, err := addressRef(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	page, err := s.w.set.Network.DescribeAddresses(ctx, backend.Scope{Account: account}, resource.AddressQuery{
		IDs: []resource.AddressID{id}, Page: resource.PageRequest{Size: 1},
	})
	if err != nil {
		return nil, toStatus(err)
	}
	if len(page.Items) == 0 {
		return nil, toStatus(resource.NotFound(resource.KindAddress, id.String()))
	}
	return addressProto(page.Items[0], projectID), nil
}

func (s *addressSrv) ListAddresses(ctx context.Context, req *networkv1.ListAddressesRequest) (*networkv1.ListAddressesResponse, error) {
	projectID, account, err := accountFromParent(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	page, err := s.w.set.Network.DescribeAddresses(ctx, backend.Scope{Account: account}, resource.AddressQuery{
		Page: resource.PageRequest{Size: listPageSize(req.GetPageSize()), Token: req.GetPageToken()},
	})
	if err != nil {
		return nil, toStatus(err)
	}
	items := make([]*networkv1.Address, 0, len(page.Items))
	for _, addr := range page.Items {
		items = append(items, addressProto(addr, projectID))
	}
	return &networkv1.ListAddressesResponse{Addresses: items, NextPageToken: page.NextToken}, nil
}

func (s *addressSrv) DeleteAddress(ctx context.Context, req *networkv1.DeleteAddressRequest) (*longrunningpb.Operation, error) {
	projectID, account, id, err := addressRef(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Network.ReleaseAddress(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.ReleaseAddressRequest{ID: id})
	if err != nil {
		return nil, toStatus(err)
	}
	return runningOp(projectID, acc.Operation, addressName(projectID, id.String()), commonv1.OperationVerb_OPERATION_VERB_DELETE, s.w.now)
}

type snapshotSrv struct {
	storagev1.UnimplementedSnapshotServiceServer
	w *loopWorld
}

func (s *snapshotSrv) CreateSnapshot(ctx context.Context, req *storagev1.CreateSnapshotRequest) (*longrunningpb.Operation, error) {
	projectID, account, err := accountFromParent(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	volID, err := resource.Parse[resource.VolumeID](lastSegment(req.GetSnapshot().GetSpec().GetVolume()))
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Compute.CreateSnapshot(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.CreateSnapshotRequest{
		VolumeID: volID, Description: req.GetSnapshot().GetSpec().GetDescription(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return runningOp(projectID, acc.Operation, snapshotName(projectID, acc.Items[0].ID.String()), commonv1.OperationVerb_OPERATION_VERB_CREATE, s.w.now)
}

func (s *snapshotSrv) GetSnapshot(ctx context.Context, req *storagev1.GetSnapshotRequest) (*storagev1.Snapshot, error) {
	projectID, account, id, err := snapshotRef(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	page, err := s.w.set.Compute.DescribeSnapshots(ctx, backend.Scope{Account: account}, resource.SnapshotQuery{
		IDs: []resource.SnapshotID{id}, Page: resource.PageRequest{Size: 1},
	})
	if err != nil {
		return nil, toStatus(err)
	}
	if len(page.Items) == 0 {
		return nil, toStatus(resource.NotFound(resource.KindSnapshot, id.String()))
	}
	return snapshotProto(page.Items[0], projectID), nil
}

func (s *snapshotSrv) ListSnapshots(ctx context.Context, req *storagev1.ListSnapshotsRequest) (*storagev1.ListSnapshotsResponse, error) {
	projectID, account, err := accountFromParent(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	page, err := s.w.set.Compute.DescribeSnapshots(ctx, backend.Scope{Account: account}, resource.SnapshotQuery{
		Page: resource.PageRequest{Size: listPageSize(req.GetPageSize()), Token: req.GetPageToken()},
	})
	if err != nil {
		return nil, toStatus(err)
	}
	items := make([]*storagev1.Snapshot, 0, len(page.Items))
	for _, snap := range page.Items {
		items = append(items, snapshotProto(snap, projectID))
	}
	return &storagev1.ListSnapshotsResponse{Snapshots: items, NextPageToken: page.NextToken}, nil
}

func (s *snapshotSrv) DeleteSnapshot(ctx context.Context, req *storagev1.DeleteSnapshotRequest) (*longrunningpb.Operation, error) {
	projectID, account, id, err := snapshotRef(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Compute.DeleteSnapshot(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.DeleteSnapshotRequest{ID: id})
	if err != nil {
		return nil, toStatus(err)
	}
	return runningOp(projectID, acc.Operation, snapshotName(projectID, id.String()), commonv1.OperationVerb_OPERATION_VERB_DELETE, s.w.now)
}

func (w *loopWorld) rememberKeyLine(id, line string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.keyLine[id] = line
}

func (w *loopWorld) keyLineOf(id string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.keyLine[id]
}

func (w *loopWorld) groupsIn(vpcID string) []resource.SecurityGroup {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]resource.SecurityGroup, 0, len(w.groups))
	for _, group := range w.groups {
		if group.VpcID.String() == vpcID {
			out = append(out, group)
		}
	}
	return out
}

func accountFromParent(parent string) (string, resource.AccountID, error) {
	projectID, err := projectOfName(parent)
	if err != nil {
		return "", resource.AccountID{}, err
	}
	account, err := accountOf(projectID)
	if err != nil {
		return "", resource.AccountID{}, err
	}
	return projectID, account, nil
}

func listPageSize(n int32) int {
	if n < 1 {
		return 50
	}
	return int(n)
}

func keyRef(name string) (string, resource.AccountID, resource.KeyPairID, error) {
	return namedRef[resource.KeyPairID](name, "keyPairs")
}

func addressRef(name string) (string, resource.AccountID, resource.AddressID, error) {
	return namedRef[resource.AddressID](name, "addresses")
}

func snapshotRef(name string) (string, resource.AccountID, resource.SnapshotID, error) {
	return namedRef[resource.SnapshotID](name, "snapshots")
}

func namedRef[T any, PT interface {
	*T
	encodingText
}](name, kind string) (string, resource.AccountID, T, error) {
	var zero T
	parts := splitSlash(name)
	if len(parts) != 6 || parts[4] != kind {
		return "", resource.AccountID{}, zero, resource.Internal(errors.New("bad " + kind + " name"))
	}
	account, err := accountOf(parts[1])
	if err != nil {
		return "", resource.AccountID{}, zero, err
	}
	id, err := resource.Parse[T, PT](parts[5])
	if err != nil {
		return "", resource.AccountID{}, zero, err
	}
	return parts[1], account, id, nil
}

type encodingText interface {
	UnmarshalText([]byte) error
}

func keyProto(key resource.KeyPair, projectID, line string) *computev1.KeyPair {
	return &computev1.KeyPair{
		Name:   keyPairName(projectID, key.ID.String()),
		Labels: nameLabels(key.Name),
		Spec:   &computev1.KeyPairSpec{PublicKey: line},
		Status: &computev1.KeyPairStatus{
			Observed:          &commonv1.ObservedState{State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY},
			FingerprintSha256: key.Fingerprint,
		},
	}
}

func addressProto(addr resource.Address, projectID string) *networkv1.Address {
	status := &networkv1.AddressStatus{
		Observed: &commonv1.ObservedState{State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY},
		Ipv4:     addr.PublicIP,
	}
	if !addr.InstanceID.IsZero() {
		status.Instance = instanceName(projectID, addr.InstanceID.String())
	}
	return &networkv1.Address{
		Name:   addressName(projectID, addr.ID.String()),
		Spec:   &networkv1.AddressSpec{IpVersion: networkv1.IpVersion_IP_VERSION_IPV4},
		Status: status,
	}
}

func snapshotProto(snap resource.Snapshot, projectID string) *storagev1.Snapshot {
	obs := commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING
	if snap.State == resource.SnapshotCompleted {
		obs = commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	}
	return &storagev1.Snapshot{
		Name: snapshotName(projectID, snap.ID.String()),
		Spec: &storagev1.SnapshotSpec{
			Volume:      volumeName(projectID, snap.VolumeID.String()),
			Description: snap.Description,
		},
		Status: &storagev1.SnapshotStatus{
			Observed: &commonv1.ObservedState{State: obs},
			SizeGib:  snap.VolumeSize,
		},
	}
}
