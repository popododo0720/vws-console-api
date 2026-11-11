package grpcclient

import (
	"context"
	"maps"
	"testing"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type partialVolumeTags struct {
	storagev1.VolumeServiceClient
	volumes  map[string]*storagev1.Volume
	fail     string
	requests []*storagev1.UpdateVolumeRequest
	applied  map[string]bool
}

func (s *partialVolumeTags) GetVolume(
	_ context.Context, req *storagev1.GetVolumeRequest, _ ...grpc.CallOption,
) (*storagev1.Volume, error) {
	return proto.Clone(s.volumes[req.GetName()]).(*storagev1.Volume), nil
}

func (s *partialVolumeTags) UpdateVolume(
	_ context.Context, req *storagev1.UpdateVolumeRequest, _ ...grpc.CallOption,
) (*longrunningpb.Operation, error) {
	s.requests = append(s.requests, proto.Clone(req).(*storagev1.UpdateVolumeRequest))
	name := req.GetVolume().GetName()
	if name == s.fail {
		s.fail = ""
		return nil, status.Error(codes.Unavailable, "storage unavailable")
	}
	if !s.applied[req.GetRequestId()] {
		s.volumes[name].Labels = maps.Clone(req.GetVolume().GetLabels())
		s.applied[req.GetRequestId()] = true
	}
	meta, err := anypb.New(&commonv1.OperationMetadata{
		Resource: name, Verb: commonv1.OperationVerb_OPERATION_VERB_UPDATE,
	})
	if err != nil {
		return nil, err
	}
	projectID, err := projectOfName(name)
	if err != nil {
		return nil, err
	}
	return &longrunningpb.Operation{
		Name:     volumeParent(projectID) + "/operations/op-0123456789abcdef",
		Metadata: meta,
	}, nil
}

func TestUntagVolumesPartialFailureRetry(t *testing.T) {
	account := mustAccount(t)
	world := &partialVolumeTags{
		volumes: map[string]*storagev1.Volume{}, applied: map[string]bool{},
	}
	ids := make([]resource.VolumeID, 0, 2)
	for _, raw := range []string{"vol-0123456789abcdef0", "vol-0fedcba9876543210"} {
		id, err := resource.Parse[resource.VolumeID](raw)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		vol := observedVolume(project(account), raw, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, "")
		vol.Labels = map[string]string{"env": "dev", labelInstance: "i-0123456789abcdef0"}
		world.volumes[vol.GetName()] = vol
	}
	first, second := volumeName(project(account), ids[0].String()), volumeName(project(account), ids[1].String())
	world.fail = second
	client := computeClient{&api{volumes: world}}
	mut := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "untag-partial", Fingerprint: "untag-partial"}
	req := resource.UntagVolumesRequest{IDs: ids, Tags: []resource.TagSelector{{Key: "env"}}}
	if _, err := client.UntagVolumes(t.Context(), mut, req); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("partial delete: %v", err)
	}
	if _, ok := world.volumes[first].Labels["env"]; ok || world.volumes[second].Labels["env"] != "dev" {
		t.Fatalf("partial labels: first=%v second=%v", world.volumes[first].Labels, world.volumes[second].Labels)
	}
	if _, err := client.UntagVolumes(t.Context(), mut, req); err != nil {
		t.Fatal(err)
	}
	if len(world.requests) != 4 || !proto.Equal(world.requests[0], world.requests[2]) ||
		!proto.Equal(world.requests[1], world.requests[3]) || len(world.applied) != 2 {
		t.Fatalf("retry requests: %v; applied: %v", world.requests, world.applied)
	}
	for _, vol := range world.volumes {
		if !maps.Equal(vol.Labels, map[string]string{labelInstance: "i-0123456789abcdef0"}) {
			t.Fatalf("labels after retry: %v", vol.Labels)
		}
	}
}
