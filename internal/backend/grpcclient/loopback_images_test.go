package grpcclient

import (
	"context"
	"sort"
	"strings"
	"sync"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// imageSrv is compute's image store in front of the fake. It holds only the
// images CreateImage copied, so a seed is never found, and it names each one
// as compute does: "img-" and the 17 digits of the fake's "ami-" id, whatever
// image_id the request sent.
type imageSrv struct {
	computev1.UnimplementedImageServiceServer
	w     *loopWorld
	mu    sync.Mutex
	names map[string]resource.ImageID
}

func (s *imageSrv) CreateImage(
	ctx context.Context, req *computev1.CreateImageRequest,
) (*longrunningpb.Operation, error) {
	projectID, account, err := accountFromParent(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	snap, err := resource.Parse[resource.SnapshotID](lastSegment(req.GetImage().GetSpec().GetSnapshot()))
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	spec := req.GetImage().GetSpec()
	acc, err := s.w.set.Compute.RegisterImage(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.RegisterImageRequest{Name: spec.GetFamily(), Description: spec.GetDescription(), SnapshotID: snap})
	if err != nil {
		return nil, toStatus(err)
	}
	name := copiedImageName(projectID, acc.Items[0].ID)
	s.mu.Lock()
	s.names[name] = acc.Items[0].ID
	s.mu.Unlock()
	return runningOp(projectID, acc.Operation, name, commonv1.OperationVerb_OPERATION_VERB_CREATE, s.w.now)
}

func (s *imageSrv) GetImage(ctx context.Context, req *computev1.GetImageRequest) (*computev1.Image, error) {
	s.mu.Lock()
	id, ok := s.names[req.GetName()]
	s.mu.Unlock()
	if !ok {
		return nil, toStatus(resource.NotFound(resource.KindImage, lastSegment(req.GetName())))
	}
	return s.read(ctx, req.GetName(), id)
}

func (s *imageSrv) ListImages(
	ctx context.Context, req *computev1.ListImagesRequest,
) (*computev1.ListImagesResponse, error) {
	prefix := req.GetParent() + "/images/"
	s.mu.Lock()
	var names []string
	for name := range s.names {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	ids := make(map[string]resource.ImageID, len(names))
	for _, name := range names {
		ids[name] = s.names[name]
	}
	s.mu.Unlock()
	sort.Strings(names)
	out := &computev1.ListImagesResponse{}
	for _, name := range names {
		img, err := s.read(ctx, name, ids[name])
		if err != nil {
			return nil, err
		}
		out.Images = append(out.Images, img)
	}
	return out, nil
}

func (s *imageSrv) read(ctx context.Context, name string, id resource.ImageID) (*computev1.Image, error) {
	account, err := accountIn(name)
	if err != nil {
		return nil, toStatus(err)
	}
	page, err := s.w.set.Compute.DescribeImages(ctx, backend.Scope{Account: account}, resource.ImageQuery{
		IDs: []resource.ImageID{id}, Page: resource.PageRequest{Size: 1},
	})
	if err != nil {
		return nil, toStatus(err)
	}
	img := page.Items[0]
	obs := commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING
	if img.State == resource.ImageAvailable {
		obs = commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	}
	return &computev1.Image{
		Name: name,
		Spec: &computev1.ImageSpec{Description: img.Description, Family: img.Name},
		Status: &computev1.ImageStatus{
			Observed: &commonv1.ObservedState{State: obs}, SizeGib: img.SizeGiB,
		},
	}, nil
}

func copiedImageName(projectID string, id resource.ImageID) string {
	return imageName(projectID, computeCopyPrefix+strings.TrimPrefix(id.String(), "ami-"))
}
