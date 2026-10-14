package grpcclient

import (
	"context"
	"errors"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// UpdateVpc serves the labels mask the way vws-network does: the labels are
// replaced. The fake merges tags, which is the same for tags that only grow.
func (s *vpcSrv) UpdateVpc(ctx context.Context, req *networkv1.UpdateVpcRequest) (*longrunningpb.Operation, error) {
	if paths := req.GetUpdateMask().GetPaths(); len(paths) != 1 || paths[0] != "labels" {
		return nil, toStatus(resource.Invalid("update_mask", "only labels"))
	}
	name := req.GetVpc().GetName()
	projectID, err := projectOfName(name)
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	id, err := resource.Parse[resource.VpcID](lastSegment(name))
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	tags := userTags(req.GetVpc().GetLabels())
	if len(tags) == 0 {
		return nil, toStatus(resource.Internal(errors.New("loopback: empty tag update")))
	}
	acc, err := s.w.set.Network.TagVpcs(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.TagVpcsRequest{IDs: []resource.VpcID{id}, Tags: tags})
	if err != nil {
		return nil, toStatus(err)
	}
	return runningOp(projectID, acc.Operation, name, commonv1.OperationVerb_OPERATION_VERB_UPDATE, s.w.now)
}

// UpdateSubnet serves the labels mask like UpdateVpc.
func (s *subnetSrv) UpdateSubnet(ctx context.Context, req *networkv1.UpdateSubnetRequest) (*longrunningpb.Operation, error) {
	if paths := req.GetUpdateMask().GetPaths(); len(paths) != 1 || paths[0] != "labels" {
		return nil, toStatus(resource.Invalid("update_mask", "only labels"))
	}
	name := req.GetSubnet().GetName()
	projectID, err := projectOfName(name)
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	id, err := resource.Parse[resource.SubnetID](lastSegment(name))
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	tags := userTags(req.GetSubnet().GetLabels())
	if len(tags) == 0 {
		return nil, toStatus(resource.Internal(errors.New("loopback: empty tag update")))
	}
	acc, err := s.w.set.Network.TagSubnets(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.TagSubnetsRequest{IDs: []resource.SubnetID{id}, Tags: tags})
	if err != nil {
		return nil, toStatus(err)
	}
	s.w.retagSub(id.String(), acc.Items[0].Tags)
	return runningOp(projectID, acc.Operation, name, commonv1.OperationVerb_OPERATION_VERB_UPDATE, s.w.now)
}

func (w *loopWorld) retagSub(id string, tags map[string]string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if snap, ok := w.sub[id]; ok {
		snap.sub.Tags = tags
		w.sub[id] = snap
	}
}
