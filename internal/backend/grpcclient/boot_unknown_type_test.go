package grpcclient

import (
	"context"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// unmappedBoot is vws-storage refusing the RunInstances boot volume the way
// its admission refuses a type no StorageClass is mapped to: gRPC
// InvalidArgument with ErrorInfo INVALID_SPEC (vws-storage#123, #124).
type unmappedBoot struct {
	refusedImage
}

func (s *unmappedBoot) CreateVolume(
	_ context.Context, req *storagev1.CreateVolumeRequest,
) (*longrunningpb.Operation, error) {
	s.image = req.GetVolume().GetSpec().GetImage()
	st, err := status.New(codes.InvalidArgument, s.msg).
		WithDetails(&errdetails.ErrorInfo{Reason: "INVALID_SPEC", Domain: "vws.dev"})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return nil, st.Err()
}

// #324 (from the #335 review): a RunInstances whose gp2 boot volume vws-storage
// refuses as an unmapped type answers the volumeType error EC2 calls
// UnknownVolumeType, as CreateVolume does. Any other storage refusal of the
// boot volume keeps its own code.
func TestRunInstancesUnmappedBootTypeIsUnknownVolumeType(t *testing.T) {
	sub := must(resource.Parse[resource.SubnetID]("subnet-01234567"))
	run := func(msg string) error {
		client := dialRefused(t, &unmappedBoot{refusedImage{msg: msg}})
		_, err := client.RunInstances(context.Background(), backend.Mutation{
			Scope: backend.Scope{Account: mustAccount(t)}, Key: "run-unmapped", Fingerprint: "fp",
		}, resource.RunInstancesRequest{
			ImageID: mustImage(t, "ami-0123456789abcdef0"), InstanceType: "vws.small", SubnetID: sub, Count: 1,
		})
		return err
	}
	unmapped := run("invalid argument: volume type gp2 is unsupported: " +
		"invalid: no StorageClass is mapped to volume type gp2")
	if e := resource.AsError(unmapped); e == nil || e.Code != resource.CodeInvalidArgument || e.Field != "volumeType" {
		t.Fatalf("unmapped boot type: got %#v, want the volumeType error (UnknownVolumeType)", e)
	}
	other := run("invalid argument: volume type gp2 needs a size from 1 to 16384 GiB")
	if e := resource.AsError(other); e == nil || e.Code != resource.CodeInvalidArgument || e.Field == "volumeType" {
		t.Fatalf("size refusal: got %#v, want InvalidArgument without the volumeType field", e)
	}
}
