package grpcclient

import (
	"context"
	"net"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// refusedImage is the operation vws-storage returns for a refused image clone:
// code 5, reason RECONCILIATION_FAILED, message "image <name> not found".
type refusedImage struct {
	networkv1.UnimplementedVpcServiceServer
	networkv1.UnimplementedSubnetServiceServer
	storagev1.UnimplementedVolumeServiceServer
	computev1.UnimplementedInstanceServiceServer
	msg       string
	retryable bool
	image     string
}

func (s *refusedImage) ListVpcs(_ context.Context, req *networkv1.ListVpcsRequest) (*networkv1.ListVpcsResponse, error) {
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	return &networkv1.ListVpcsResponse{Vpcs: []*networkv1.Vpc{{
		Name: vpcName(projectID, "vpc-01234567"),
	}}}, nil
}

func (s *refusedImage) ListSubnets(_ context.Context, req *networkv1.ListSubnetsRequest) (*networkv1.ListSubnetsResponse, error) {
	return &networkv1.ListSubnetsResponse{Subnets: []*networkv1.Subnet{{
		Name: req.GetParent() + "/subnets/subnet-01234567",
	}}}, nil
}

func (s *refusedImage) CreateVolume(_ context.Context, req *storagev1.CreateVolumeRequest) (*longrunningpb.Operation, error) {
	s.image = req.GetVolume().GetSpec().GetImage()
	st, err := imageCloneStatus(s.msg, s.retryable)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &longrunningpb.Operation{
		Done:   true,
		Result: &longrunningpb.Operation_Error{Error: st.Proto()},
	}, nil
}

func imageCloneStatus(msg string, retryable bool) (*status.Status, error) {
	return status.New(codes.NotFound, msg).WithDetails(
		&errdetails.ErrorInfo{Reason: "RECONCILIATION_FAILED", Domain: "vws.dev"},
		&commonv1.ReconciliationFailure{Retryable: retryable},
	)
}

func imageCloneMessage(t *testing.T) string {
	t.Helper()
	return "image " + imageName(project(mustAccount(t)), "ami-0123456789abcdef0") + " not found"
}

func wantImageNotFound(t *testing.T, err error, msg string) {
	t.Helper()
	e := resource.AsError(err)
	if e == nil || e.Code != resource.CodeNotFound || e.Kind != resource.KindImage || e.Message != msg {
		t.Fatalf("got %#v, want NotFound image %q", e, msg)
	}
}

func dialRefused(t *testing.T, boot *refusedImage) computeClient {
	t.Helper()
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	networkv1.RegisterVpcServiceServer(srv, boot)
	networkv1.RegisterSubnetServiceServer(srv, boot)
	storagev1.RegisterVolumeServiceServer(srv, boot)
	computev1.RegisterInstanceServiceServer(srv, boot)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///refused",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return computeClient{&api{
		instances: computev1.NewInstanceServiceClient(conn),
		volumes:   storagev1.NewVolumeServiceClient(conn),
		subnets:   networkv1.NewSubnetServiceClient(conn),
		vpcs:      networkv1.NewVpcServiceClient(conn),
	}}
}

func TestRefusedImageCloneIsInvalidAMI(t *testing.T) {
	msg := imageCloneMessage(t)
	sub := must(resource.Parse[resource.SubnetID]("subnet-01234567"))
	run := func(retryable bool) error {
		boot := &refusedImage{msg: msg, retryable: retryable}
		client := dialRefused(t, boot)
		_, err := client.RunInstances(context.Background(), backend.Mutation{
			Scope: backend.Scope{Account: mustAccount(t)}, Key: "run-absent", Fingerprint: "fp",
		}, resource.RunInstancesRequest{
			ImageID: mustImage(t, "ami-0123456789abcdef0"), InstanceType: "vws.small", SubnetID: sub, Count: 1,
		})
		if boot.image != imageName(project(mustAccount(t)), "ami-0123456789abcdef0") {
			t.Fatalf("volume source %q", boot.image)
		}
		return err
	}
	t.Run("RunInstances", func(t *testing.T) {
		wantImageNotFound(t, run(false), msg)
	})
	t.Run("RunInstancesRetryable", func(t *testing.T) {
		wantImageNotFound(t, run(true), msg)
	})
	t.Run("CreateVolume", func(t *testing.T) {
		boot := &refusedImage{msg: msg}
		client := dialRefused(t, boot)
		_, err := client.CreateVolume(context.Background(), backend.Mutation{
			Scope: backend.Scope{Account: mustAccount(t)}, Key: "vol-absent", Fingerprint: "fp",
		}, resource.CreateVolumeRequest{SizeGiB: 8, Zone: resource.ZoneName, Type: resource.VolumeGP2})
		wantImageNotFound(t, err, msg)
	})
	for _, action := range []struct {
		name string
		verb commonv1.OperationVerb
		res  string
		want resource.Action
	}{
		{"CreateVolumeOperation", commonv1.OperationVerb_OPERATION_VERB_CREATE, volumeName(project(mustAccount(t)), "vol-0123456789abcdef0"), resource.ActionCreateVolume},
		{"RunInstancesOperation", commonv1.OperationVerb_OPERATION_VERB_CREATE, instanceName(project(mustAccount(t)), "i-0123456789abcdef0"), resource.ActionRunInstances},
	} {
		t.Run(action.name, func(t *testing.T) {
			st, err := imageCloneStatus(msg, true)
			if err != nil {
				t.Fatal(err)
			}
			meta, err := anypb.New(&commonv1.OperationMetadata{
				Resource:   action.res,
				Verb:       action.verb,
				CreateTime: timestamppb.Now(),
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err := operationFrom(&longrunningpb.Operation{
				Name:     operationName(project(mustAccount(t)), "5f0c2a9e1b7d4c3a"),
				Metadata: meta,
				Done:     true,
				Result:   &longrunningpb.Operation_Error{Error: st.Proto()},
			}, resource.ServiceCompute)
			if err != nil {
				t.Fatal(err)
			}
			if got.Action != action.want || got.State != resource.OperationFailed {
				t.Fatalf("action %s state %s", got.Action, got.State)
			}
			wantImageNotFound(t, got.Error, msg)
		})
	}
}

func TestReconciliationMappingsStay(t *testing.T) {
	imageMsg := imageCloneMessage(t)
	cases := []struct {
		name      string
		code      codes.Code
		reason    string
		msg       string
		retryable bool
		domain    string
		want      resource.Code
		kind      resource.Kind
	}{
		{"internal image sentence", codes.Internal, "RECONCILIATION_FAILED", imageMsg, false, "vws.dev", resource.CodeInternal, 0},
		{"not found volume sentence", codes.NotFound, "RECONCILIATION_FAILED", "volume vol-0123456789abcdef0 not found", false, "vws.dev", resource.CodeInternal, 0},
		{"image sentence without a name", codes.NotFound, "RECONCILIATION_FAILED", "image not found", false, "vws.dev", resource.CodeInternal, 0},
		{"image sentence with an empty name", codes.NotFound, "RECONCILIATION_FAILED", "image  not found", false, "vws.dev", resource.CodeInternal, 0},
		{"retryable volume sentence", codes.NotFound, "RECONCILIATION_FAILED", "volume vol-0123456789abcdef0 not found", true, "vws.dev", resource.CodeUnavailable, 0},
		{"retryable plain", codes.Unavailable, "RECONCILIATION_FAILED", "not ready", true, "vws.dev", resource.CodeUnavailable, 0},
		{"permanent plain", codes.Internal, "RECONCILIATION_FAILED", "failed", false, "vws.dev", resource.CodeInternal, 0},
		{"resource not found keeps no kind", codes.NotFound, "RESOURCE_NOT_FOUND", imageMsg, false, "vws.dev", resource.CodeNotFound, 0},
		{"dependency stays conflict", codes.FailedPrecondition, "DEPENDENCY_NOT_READY", "instance cannot be stopped", false, "vws.dev", resource.CodeConflict, 0},
		{"already exists", codes.AlreadyExists, "ALREADY_EXISTS", "exists", false, "vws.dev", resource.CodeAlreadyExists, 0},
		{"invalid spec", codes.InvalidArgument, "INVALID_SPEC", "bad", false, "vws.dev", resource.CodeInvalidArgument, 0},
		{"quota", codes.ResourceExhausted, "QUOTA_EXCEEDED", "quota", false, "vws.dev", resource.CodeResourceExhausted, 0},
		{"idempotency", codes.Aborted, "IDEMPOTENCY_CONFLICT", "mismatch", false, "vws.dev", resource.CodeIdempotencyMismatch, 0},
		{"bare not found", codes.NotFound, "", "missing", false, "", resource.CodeNotFound, 0},
		{"unknown reason uses the code", codes.NotFound, "SOMETHING_ELSE", imageMsg, false, "vws.dev", resource.CodeNotFound, 0},
		{"foreign domain uses the code", codes.NotFound, "RECONCILIATION_FAILED", imageMsg, false, "other.dev", resource.CodeNotFound, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := fromRPC(statusFor(t, tc.code, tc.reason, tc.domain, tc.msg, tc.retryable))
			e := resource.AsError(err)
			if e == nil || e.Code != tc.want || e.Kind != tc.kind || e.Message != tc.msg {
				t.Fatalf("got %#v, want code %v kind %v message %q", e, tc.want, tc.kind, tc.msg)
			}
		})
	}
	st, err := status.New(codes.NotFound, "volume vol-0123456789abcdef0 not found").WithDetails(
		&errdetails.ErrorInfo{Reason: "RECONCILIATION_FAILED", Domain: "vws.dev"},
		&commonv1.ReconciliationFailure{Retryable: false},
	)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := anypb.New(&commonv1.OperationMetadata{
		Resource:   volumeName(project(mustAccount(t)), "vol-0123456789abcdef0"),
		Verb:       commonv1.OperationVerb_OPERATION_VERB_CREATE,
		CreateTime: timestamppb.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := operationFrom(&longrunningpb.Operation{
		Name:     operationName(project(mustAccount(t)), "5f0c2a9e1b7d4c3a"),
		Metadata: meta,
		Done:     true,
		Result:   &longrunningpb.Operation_Error{Error: st.Proto()},
	}, resource.ServiceCompute)
	if err != nil {
		t.Fatal(err)
	}
	if got.Action != resource.ActionCreateVolume || got.Error == nil || got.Error.Code != resource.CodeInternal || got.Error.Kind != 0 {
		t.Fatalf("%+v", got)
	}
}

func statusFor(t *testing.T, code codes.Code, reason, domain, msg string, retryable bool) error {
	t.Helper()
	if domain == "" {
		return status.Error(code, msg)
	}
	info := &errdetails.ErrorInfo{Reason: reason, Domain: domain}
	var st *status.Status
	var err error
	if reason == "RECONCILIATION_FAILED" {
		st, err = status.New(code, msg).WithDetails(info, &commonv1.ReconciliationFailure{Retryable: retryable})
	} else {
		st, err = status.New(code, msg).WithDetails(info)
	}
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}
