package grpcclient

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	op := resource.Operation{
		ID: id, Action: resource.ActionStopInstances, State: resource.OperationFailed,
		OwnerID: owner, Targets: []resource.Ref{inst.Ref()},
		Error:      &resource.Error{Code: resource.CodeConflict, Message: "instance cannot be stopped"},
		CreateTime: time.Unix(1_700_000_000, 0).UTC(),
		UpdateTime: time.Unix(1_700_000_001, 0).UTC(),
	}
	got, err := operationModel(operationProto(op))
	if err != nil {
		t.Fatal(err)
	}
	if got.OwnerID != owner || got.ID != id || got.Error == nil || got.Error.Code != resource.CodeConflict || got.Error.Message != op.Error.Message {
		t.Fatalf("%+v", got)
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
