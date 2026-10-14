package grpcclient

import (
	"context"
	"errors"
	"strings"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (s *volumeSrv) GetVolume(ctx context.Context, req *storagev1.GetVolumeRequest) (*storagev1.Volume, error) {
	projectID, account, id, err := volumeRef(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	page, err := s.w.set.Compute.DescribeVolumes(ctx, backend.Scope{Account: account}, resource.VolumeQuery{
		IDs: []resource.VolumeID{id}, Page: resource.PageRequest{Size: 1},
	})
	if err != nil {
		return nil, toStatus(err)
	}
	if len(page.Items) == 0 {
		return nil, toStatus(resource.NotFound(resource.KindVolume, id.String()))
	}
	return volumeProto(page.Items[0], projectID), nil
}

func (s *volumeSrv) ListVolumes(ctx context.Context, req *storagev1.ListVolumesRequest) (*storagev1.ListVolumesResponse, error) {
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	size := int(req.GetPageSize())
	if size < 1 {
		size = 50
	}
	page, err := s.w.set.Compute.DescribeVolumes(ctx, backend.Scope{Account: account}, resource.VolumeQuery{
		Page: resource.PageRequest{Size: size, Token: req.GetPageToken()},
	})
	if err != nil {
		return nil, toStatus(err)
	}
	items := make([]*storagev1.Volume, 0, len(page.Items))
	for _, vol := range page.Items {
		items = append(items, volumeProto(vol, projectID))
	}
	items = append(items, s.w.bootsFor(projectID)...)
	return &storagev1.ListVolumesResponse{Volumes: items, NextPageToken: page.NextToken}, nil
}

func (s *volumeSrv) UpdateVolume(ctx context.Context, req *storagev1.UpdateVolumeRequest) (*longrunningpb.Operation, error) {
	projectID, account, id, err := volumeRef(req.GetVolume().GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Compute.ModifyVolume(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.ModifyVolumeRequest{ID: id, SizeGiB: req.GetVolume().GetSpec().GetSizeGib()})
	if err != nil {
		return nil, toStatus(err)
	}
	return runningOp(projectID, acc.Operation, volumeName(projectID, id.String()), commonv1.OperationVerb_OPERATION_VERB_UPDATE, s.w.now)
}

func (s *volumeSrv) DeleteVolume(ctx context.Context, req *storagev1.DeleteVolumeRequest) (*longrunningpb.Operation, error) {
	projectID, account, id, err := volumeRef(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Compute.DeleteVolume(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.DeleteVolumeRequest{ID: id})
	if err != nil {
		return nil, toStatus(err)
	}
	return runningOp(projectID, acc.Operation, volumeName(projectID, id.String()), commonv1.OperationVerb_OPERATION_VERB_DELETE, s.w.now)
}

func (s *vpcSrv) GetVpc(ctx context.Context, req *networkv1.GetVpcRequest) (*networkv1.Vpc, error) {
	projectID, err := projectOfName(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	idText := lastSegment(req.GetName())
	if id, parseErr := resource.Parse[resource.VpcID](idText); parseErr == nil {
		page, err := s.w.set.Network.DescribeVpcs(ctx, backend.Scope{Account: account}, resource.VpcQuery{
			IDs: []resource.VpcID{id}, Page: resource.PageRequest{Size: 1},
		})
		if err != nil {
			return nil, toStatus(err)
		}
		if len(page.Items) == 0 {
			return nil, toStatus(resource.NotFound(resource.KindVpc, idText))
		}
		return vpcProto(page.Items[0], projectID), nil
	}
	if cidr, ok := s.w.cidrOf(req.GetName()); ok {
		return &networkv1.Vpc{
			Name: req.GetName(),
			Spec: &networkv1.VpcSpec{Ipv4Cidr: cidr},
			Status: &networkv1.VpcStatus{Observed: &commonv1.ObservedState{
				State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
			}},
		}, nil
	}
	return nil, toStatus(resource.NotFound(resource.KindVpc, idText))
}

func (s *vpcSrv) DeleteVpc(ctx context.Context, req *networkv1.DeleteVpcRequest) (*longrunningpb.Operation, error) {
	projectID, err := projectOfName(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	id, err := resource.Parse[resource.VpcID](lastSegment(req.GetName()))
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Network.DeleteVpc(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.DeleteVpcRequest{ID: id})
	if err != nil {
		return nil, toStatus(err)
	}
	return runningOp(projectID, acc.Operation, vpcName(projectID, id.String()), commonv1.OperationVerb_OPERATION_VERB_DELETE, s.w.now)
}

type groupSrv struct {
	networkv1.UnimplementedSecurityGroupServiceServer
	w *loopWorld
}

func (s *groupSrv) CreateSecurityGroup(ctx context.Context, req *networkv1.CreateSecurityGroupRequest) (*longrunningpb.Operation, error) {
	if !s.w.has(req.GetParent()) {
		return nil, toStatus(resource.NotFound(resource.KindVpc, "vpc"))
	}
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	vpcID, err := resource.Parse[resource.VpcID](lastSegment(req.GetParent()))
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Network.CreateSecurityGroup(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.CreateSecurityGroupRequest{Name: req.GetSecurityGroup().GetSpec().GetDescription(), VpcID: vpcID})
	if err != nil {
		return nil, toStatus(err)
	}
	s.w.saveGroup(acc.Items[0])
	s.w.rememberSubnet(acc.Items[0].ID.String(), vpcID.String())
	return runningOp(projectID, acc.Operation, securityGroupName(projectID, vpcID.String(), acc.Items[0].ID.String()), commonv1.OperationVerb_OPERATION_VERB_CREATE, s.w.now)
}

func (s *groupSrv) GetSecurityGroup(_ context.Context, req *networkv1.GetSecurityGroupRequest) (*networkv1.SecurityGroup, error) {
	projectID, err := projectOfName(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	group, ok := s.w.group(lastSegment(req.GetName()), account)
	if !ok {
		return nil, toStatus(resource.NotFound(resource.KindSecurityGroup, lastSegment(req.GetName())))
	}
	return groupProto(group, projectID), nil
}

func (s *groupSrv) UpdateSecurityGroup(ctx context.Context, req *networkv1.UpdateSecurityGroupRequest) (*longrunningpb.Operation, error) {
	projectID, err := projectOfName(req.GetSecurityGroup().GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	id, err := resource.Parse[resource.SecurityGroupID](lastSegment(req.GetSecurityGroup().GetName()))
	if err != nil {
		return nil, toStatus(err)
	}
	rules := req.GetSecurityGroup().GetSpec().GetRules()
	if len(rules) == 0 {
		return nil, toStatus(resource.Invalid("ipProtocol", "required"))
	}
	if err := ctx.Err(); err != nil {
		return nil, toStatus(err)
	}
	group, ok := s.w.group(id.String(), account)
	if !ok {
		return nil, toStatus(resource.NotFound(resource.KindSecurityGroup, id.String()))
	}
	decoded := make([]resource.IngressRule, 0, len(rules))
	for _, rule := range rules {
		decoded = append(decoded, resource.IngressRule{
			Protocol: protocolName(rule.GetProtocol()),
			FromPort: int(rule.GetFromPort()),
			ToPort:   int(rule.GetToPort()),
			Cidr:     rule.GetCidr(),
		})
	}
	group.Rules = decoded
	s.w.saveGroup(group)
	return runningNamed(projectID, req.GetRequestId(), req.GetSecurityGroup().GetName(), commonv1.OperationVerb_OPERATION_VERB_UPDATE, s.w.now)
}

type keySrv struct {
	computev1.UnimplementedKeyPairServiceServer
	w *loopWorld
}

func (s *keySrv) CreateKeyPair(ctx context.Context, req *computev1.CreateKeyPairRequest) (*longrunningpb.Operation, error) {
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	name := joinName(req.GetKeyPair().GetLabels())
	if name == "" {
		return nil, toStatus(resource.Invalid("keyName", "required"))
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Compute.CreateKeyPair(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.CreateKeyPairRequest{Name: name})
	if err != nil {
		return nil, toStatus(err)
	}
	if fp, ok := fingerprintOfPublicLine(req.GetKeyPair().GetSpec().GetPublicKey()); ok {
		s.w.rememberKeyFP(acc.Items[0].ID.String(), fp)
	}
	return runningOp(projectID, acc.Operation, keyPairName(projectID, acc.Items[0].ID.String()), commonv1.OperationVerb_OPERATION_VERB_CREATE, s.w.now)
}

func (w *loopWorld) cidrOf(name string) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	cidr, ok := w.vpcCIDR[name]
	return cidr, ok
}

func (w *loopWorld) saveGroup(group resource.SecurityGroup) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.groups[group.ID.String()] = group
}

func (w *loopWorld) group(id string, owner resource.AccountID) (resource.SecurityGroup, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	group, ok := w.groups[id]
	if !ok || group.OwnerID != owner {
		return resource.SecurityGroup{}, false
	}
	return group, true
}

func groupProto(group resource.SecurityGroup, projectID string) *networkv1.SecurityGroup {
	rules := make([]*networkv1.SecurityGroupRule, 0, len(group.Rules))
	for i, rule := range group.Rules {
		protocol, _ := protocolOf(rule.Protocol)
		rules = append(rules, &networkv1.SecurityGroupRule{
			Id:        "r" + hexByte(i),
			Direction: networkv1.Direction_DIRECTION_INGRESS,
			Protocol:  protocol,
			FromPort:  int32(rule.FromPort),
			ToPort:    int32(rule.ToPort),
			Target:    &networkv1.SecurityGroupRule_Cidr{Cidr: rule.Cidr},
		})
	}
	return &networkv1.SecurityGroup{
		Name: securityGroupName(projectID, group.VpcID.String(), group.ID.String()),
		Spec: &networkv1.SecurityGroupSpec{Description: group.Name, Rules: rules},
		Status: &networkv1.SecurityGroupStatus{Observed: &commonv1.ObservedState{
			State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		}},
	}
}

func joinName(labels map[string]string) string {
	keys := []string{"keyname", "keyname2", "keyname3", "keyname4", "keyname5"}
	var b strings.Builder
	for _, key := range keys {
		part := labels[key]
		if part == "" {
			break
		}
		b.WriteString(part)
	}
	return b.String()
}

func hexByte(n int) string {
	const digits = "0123456789abcdef"
	if n < 0 {
		n = 0
	}
	return string([]byte{digits[(n/16)%16], digits[n%16]})
}

func volumeRef(name string) (string, resource.AccountID, resource.VolumeID, error) {
	parts := splitSlash(name)
	if len(parts) != 6 || parts[4] != "volumes" {
		return "", resource.AccountID{}, resource.VolumeID{}, resource.Internal(errors.New("bad volume name"))
	}
	account, err := accountOf(parts[1])
	if err != nil {
		return "", resource.AccountID{}, resource.VolumeID{}, err
	}
	id, err := resource.Parse[resource.VolumeID](parts[5])
	if err != nil {
		return "", resource.AccountID{}, resource.VolumeID{}, err
	}
	return parts[1], account, id, nil
}
