package grpcclient

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestOperationFailureRoundTrip(t *testing.T) {
	owner, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.NewOperationID(resource.ServiceCompute, "5f0c2a9e1b7d4c3a")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := resource.Parse[resource.InstanceID]("i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	st, err := status.New(codes.FailedPrecondition, "instance cannot be stopped").WithDetails(&errdetails.ErrorInfo{
		Reason: "DEPENDENCY_NOT_READY",
		Domain: "vws.dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	meta, err := anypb.New(&commonv1.OperationMetadata{
		Resource:   instanceName(project(owner), inst.String()),
		Verb:       commonv1.OperationVerb_OPERATION_VERB_UPDATE,
		CreateTime: timestamppb.New(time.Unix(1_700_000_000, 0)),
		EndTime:    timestamppb.New(time.Unix(1_700_000_001, 0)),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := operationFrom(&longrunningpb.Operation{
		Name:     operationName(project(owner), id.Local()),
		Metadata: meta,
		Done:     true,
		Result:   &longrunningpb.Operation_Error{Error: st.Proto()},
	}, resource.ServiceCompute)
	if err != nil {
		t.Fatal(err)
	}
	if got.OwnerID != owner || got.ID != id || got.Action != resource.ActionStopInstances || got.State != resource.OperationFailed {
		t.Fatalf("%+v", got)
	}
	if got.Error == nil || got.Error.Code != resource.CodeConflict || got.Error.Message != "instance cannot be stopped" {
		t.Fatalf("%+v", got.Error)
	}
}

func TestCallGetsADeadline(t *testing.T) {
	err := withDeadline(context.Background(), "/vws.test", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("missing deadline")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBareResourceExhaustedStaysRetryable(t *testing.T) {
	err := fromRPC(status.Error(codes.ResourceExhausted, "quota"))
	if resource.CodeOf(err) != resource.CodeResourceExhausted {
		t.Fatalf("got %v", err)
	}
}

func TestProjectRoundTrip(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	got, err := accountOf(project(account))
	if err != nil || got != account {
		t.Fatalf("%s %v", got, err)
	}
}

func TestVpcParentCIDR(t *testing.T) {
	id, cidr, err := vpcForCIDR("10.2.0.0/24")
	if err != nil || id != "vpc-10-2-0-0-16" || cidr != "10.2.0.0/16" {
		t.Fatalf("%s %s %v", id, cidr, err)
	}
	if _, _, err := vpcForCIDR("10.0.0.0/8"); err == nil {
		t.Fatal("a /8 has no parent shorter by eight bits")
	}
}

func TestOperationLocalUUID(t *testing.T) {
	local, err := operationLocal("projects/a123456789012/operations/01234567-89ab-cdef-0123-456789abcdef")
	if err != nil || local != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("%s %v", local, err)
	}
}

func TestOperationLocalServiceNames(t *testing.T) {
	const hex16 = "0123456789abcdef"
	const hex32 = "0123456789abcdef0123456789abcdef"
	uuid := "01234567-89ab-cdef-0123-456789abcdef"
	cases := []struct {
		name string
		want string
	}{
		{"projects/a123456789012/operations/op-" + hex16, hex16},
		{"projects/a123456789012/operations/op-" + hex32, hex32},
		{"projects/a123456789012/operations/op-" + uuid, hex32},
		{"projects/a123456789012/operations/" + hex16, hex16},
		{"projects/a123456789012/operations/" + hex32, hex32},
		{"projects/a123456789012/operations/" + uuid, hex32},
	}
	for _, tc := range cases {
		local, err := operationLocal(tc.name)
		if err != nil || local != tc.want {
			t.Fatalf("%s: %s %v", tc.name, local, err)
		}
	}
	rejected := []string{
		"projects/a123456789012/operations/op-" + strings.ToUpper(hex16),
		"projects/a123456789012/operations/OP-" + hex16,
		"projects/a123456789012/operations/op-0123",
		"projects/a123456789012/operations/op-op-" + hex16,
		"projects/a123456789012/operations/" + strings.ToUpper(uuid),
		"projects/a123456789012/operations/not-an-operation",
	}
	for _, name := range rejected {
		_, err := operationLocal(name)
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for _, local := range []string{hex16, hex32} {
		name := operationName("a123456789012", local)
		got, err := operationLocal(name)
		if err != nil || got != local {
			t.Fatalf("round trip %s: %s %v", name, got, err)
		}
	}
	if seg := canonicalOperationSegment(hex16); seg != "op-"+hex16 {
		t.Fatalf("compute segment %s", seg)
	}
	if seg := canonicalOperationSegment(hex32); seg != uuid {
		t.Fatalf("storage segment %s", seg)
	}
}

func TestObjectMaskMatches(t *testing.T) {
	if !objectMaskMatches(objectUpdateMask()) {
		t.Fatal("client mask")
	}
	if !objectMaskMatches(nil) || !objectMaskMatches(&fieldmaskpb.FieldMask{}) {
		t.Fatal("empty mask")
	}
	if objectMaskMatches(&fieldmaskpb.FieldMask{Paths: []string{"spec"}}) {
		t.Fatal("spec-only mask")
	}
}

func TestErrorInfoNotFound(t *testing.T) {
	st, err := status.New(codes.NotFound, "missing").WithDetails(&errdetails.ErrorInfo{
		Reason: "RESOURCE_NOT_FOUND",
		Domain: "vws.dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resource.CodeOf(fromRPC(st.Err())) != resource.CodeNotFound {
		t.Fatalf("got %v", fromRPC(st.Err()))
	}
}

func TestInstanceStateMapping(t *testing.T) {
	cases := []struct {
		state resource.InstanceState
		obs   commonv1.ReconciliationState
		power computev1.InstancePower
	}{
		{resource.InstancePending, commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING, computev1.InstancePower_INSTANCE_POWER_RUNNING},
		{resource.InstanceRunning, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, computev1.InstancePower_INSTANCE_POWER_RUNNING},
		{resource.InstanceStopping, commonv1.ReconciliationState_RECONCILIATION_STATE_RECONCILING, computev1.InstancePower_INSTANCE_POWER_STOPPED},
		{resource.InstanceStopped, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, computev1.InstancePower_INSTANCE_POWER_STOPPED},
	}
	for _, tc := range cases {
		obs, power := instanceObserved(tc.state)
		if obs != tc.obs || power != tc.power {
			t.Fatalf("%s -> %s %s", tc.state, obs, power)
		}
		got, err := instanceStateOf(obs, power)
		if err != nil || got != tc.state {
			t.Fatalf("%s: %s %v", tc.state, got, err)
		}
	}
}
