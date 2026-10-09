package cloud

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestIdempotencyGolden(t *testing.T) {
	c, token, req := fixedRequest(t)
	norm, err := req.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	m, err := mutation(c, token, norm)
	if err != nil {
		t.Fatal(err)
	}
	const (
		wantKey = "94c3209c346d75f3f030451b930a36602285e71618d0cee45f33cbe0f4e708a4"
		wantFP  = "9f068d595c17c98b5837692cfe502433132f4c334cd8e912d7028620264494d2"
	)
	if m.Key != wantKey || m.Fingerprint != wantFP {
		t.Fatalf("derivation changed key=%s fingerprint=%s", m.Key, m.Fingerprint)
	}
}

func TestRestartReplaysOperation(t *testing.T) {
	w := world(t)
	req := runReq(t)
	token := token(t, "launch-web-1")
	caller := caller(t)
	ctx := context.Background()

	firstSvc := New(Config{Backends: w.Set()})
	first, err := firstSvc.RunInstances(ctx, caller, token, req)
	if err != nil {
		t.Fatal(err)
	}
	secondSvc := New(Config{Backends: w.Set()})
	second, err := secondSvc.RunInstances(ctx, caller, token, req)
	if err != nil {
		t.Fatal(err)
	}
	if second.Operation.ID != first.Operation.ID || second.Items[0].ID != first.Items[0].ID {
		t.Fatal("restarted process did not replay the operation")
	}
	op, err := secondSvc.GetOperation(ctx, caller, first.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != resource.OperationSucceeded {
		t.Fatalf("state %s", op.State)
	}
	page, err := secondSvc.DescribeInstances(ctx, caller, resource.InstanceQuery{IDs: []resource.InstanceID{first.Items[0].ID}})
	if err != nil {
		t.Fatal(err)
	}
	if page.Items[0].State != resource.InstanceRunning || page.Items[0].InstanceType != "vws.small" {
		t.Fatalf("%+v", page.Items[0])
	}
}

func TestForeignAccountIsInternal(t *testing.T) {
	img, _ := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	sub, _ := resource.Parse[resource.SubnetID]("subnet-0123456789abcdef0")
	id, _ := resource.Parse[resource.InstanceID]("i-0123456789abcdef0")
	other, _ := resource.Parse[resource.AccountID]("210987654321")
	opID, _ := resource.NewOperationID(resource.ServiceCompute, "5f0c2a9e1b7d4c3a")
	stub := foreignCompute{
		acc: resource.Accepted[resource.Instance]{
			Operation: resource.Operation{
				ID: opID, Action: resource.ActionRunInstances, State: resource.OperationRunning,
				Targets: []resource.Ref{id.Ref()},
			},
			Items: []resource.Instance{{
				ID: id, OwnerID: other, ImageID: img, InstanceType: "vws.small", SubnetID: sub, State: resource.InstancePending,
			}},
		},
	}
	svc := New(Config{Backends: backend.Set{Compute: stub}})
	_, err := svc.RunInstances(context.Background(), caller(t), token(t, "launch-web-1"), runReq(t))
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("got %v", err)
	}
}

type foreignCompute struct {
	acc resource.Accepted[resource.Instance]
}

func (f foreignCompute) RunInstances(context.Context, backend.Mutation, resource.RunInstancesRequest) (resource.Accepted[resource.Instance], error) {
	return f.acc, nil
}

func (foreignCompute) StopInstances(context.Context, backend.Mutation, resource.StopInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	return resource.Accepted[resource.InstanceStateChange]{}, errors.New("unused")
}

func (foreignCompute) DescribeInstances(context.Context, backend.Scope, resource.InstanceQuery) (resource.Page[resource.Instance], error) {
	return resource.Page[resource.Instance]{}, errors.New("unused")
}

func (foreignCompute) GetOperation(context.Context, backend.Scope, resource.OperationID) (resource.Operation, error) {
	return resource.Operation{}, errors.New("unused")
}

func world(t *testing.T) *fake.World {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	return fake.New(fake.Options{
		Now:     func() time.Time { return now },
		Entropy: bytes.NewReader(bytes.Repeat([]byte{0x22}, 1<<12)),
	})
}

func caller(t *testing.T) resource.Caller {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return resource.Caller{Account: account, Subject: "dev"}
}

func token(t *testing.T, s string) resource.ClientToken {
	t.Helper()
	tok, err := resource.Parse[resource.ClientToken](s)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func runReq(t *testing.T) resource.RunInstancesRequest {
	t.Helper()
	img, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	sub, err := resource.Parse[resource.SubnetID]("subnet-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	return resource.RunInstancesRequest{ImageID: img, InstanceType: "vws.small", SubnetID: sub, Count: 1}
}

func fixedRequest(t *testing.T) (resource.Caller, resource.ClientToken, resource.RunInstancesRequest) {
	t.Helper()
	return caller(t), token(t, "launch-web-1"), runReq(t)
}
