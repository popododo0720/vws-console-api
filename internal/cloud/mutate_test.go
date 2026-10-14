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
		wantKey = "3a70cf20504b660b87790b3079f89afbf17466db251477f98e1971b8899ce021"
		wantFP  = "9bf621dd437968fdf7d1ce073d19d2496bf2abd3355be85e7896641cc4a57ae8"
	)
	if m.Key != wantKey || m.Fingerprint != wantFP {
		t.Fatalf("derivation changed key=%s fingerprint=%s", m.Key, m.Fingerprint)
	}
}

func TestEmptyTagChangesFingerprint(t *testing.T) {
	c, token, req := fixedRequest(t)
	bare, err := req.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	tagged := bare
	tagged.Tags = map[string]string{"env": ""}
	a, err := mutation(c, token, bare)
	if err != nil {
		t.Fatal(err)
	}
	b, err := mutation(c, token, tagged)
	if err != nil {
		t.Fatal(err)
	}
	if a.Key != b.Key {
		t.Fatal("tag values changed the idempotency key")
	}
	if a.Fingerprint == b.Fingerprint {
		t.Fatal("empty tag value collapsed to no tags")
	}
}

func TestRestartReplaysOperation(t *testing.T) {
	w := world(t)
	req := runReq(t)
	launchToken := token(t, "launch-web-1")
	caller := caller(t)
	ctx := context.Background()

	firstSvc := New(Config{Backends: w.Set()})
	subnet, err := firstSvc.CreateSubnet(ctx, caller, token(t, "subnet-web-1"), resource.CreateSubnetRequest{Cidr: "10.1.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	req.SubnetID = subnet.Items[0].ID
	first, err := firstSvc.RunInstances(ctx, caller, launchToken, req)
	if err != nil {
		t.Fatal(err)
	}
	secondSvc := New(Config{Backends: w.Set()})
	second, err := secondSvc.RunInstances(ctx, caller, launchToken, req)
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
	op  resource.Operation
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

func (foreignCompute) StartInstances(context.Context, backend.Mutation, resource.StartInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	return resource.Accepted[resource.InstanceStateChange]{}, errors.New("unused")
}

func (foreignCompute) TerminateInstances(context.Context, backend.Mutation, resource.TerminateInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	return resource.Accepted[resource.InstanceStateChange]{}, errors.New("unused")
}

func (foreignCompute) CreateVolume(context.Context, backend.Mutation, resource.CreateVolumeRequest) (resource.Accepted[resource.Volume], error) {
	return resource.Accepted[resource.Volume]{}, errors.New("unused")
}

func (foreignCompute) AttachVolume(context.Context, backend.Mutation, resource.AttachVolumeRequest) (resource.Accepted[resource.Volume], error) {
	return resource.Accepted[resource.Volume]{}, errors.New("unused")
}

func (foreignCompute) ModifyVolume(context.Context, backend.Mutation, resource.ModifyVolumeRequest) (resource.Accepted[resource.Volume], error) {
	return resource.Accepted[resource.Volume]{}, errors.New("unused")
}

func (foreignCompute) DeleteVolume(context.Context, backend.Mutation, resource.DeleteVolumeRequest) (resource.Accepted[resource.Volume], error) {
	return resource.Accepted[resource.Volume]{}, errors.New("unused")
}

func (foreignCompute) DescribeVolumes(context.Context, backend.Scope, resource.VolumeQuery) (resource.Page[resource.Volume], error) {
	return resource.Page[resource.Volume]{}, errors.New("unused")
}

func (foreignCompute) DescribeImages(context.Context, backend.Scope, resource.ImageQuery) (resource.Page[resource.Image], error) {
	return resource.Page[resource.Image]{}, errors.New("unused")
}

func (foreignCompute) CreateKeyPair(context.Context, backend.Mutation, resource.CreateKeyPairRequest) (resource.Accepted[resource.KeyPair], error) {
	return resource.Accepted[resource.KeyPair]{}, errors.New("unused")
}

func (foreignCompute) DeleteKeyPair(context.Context, backend.Mutation, resource.DeleteKeyPairRequest) (resource.Accepted[resource.KeyPair], error) {
	return resource.Accepted[resource.KeyPair]{}, errors.New("unused")
}

func (foreignCompute) DescribeKeyPairs(context.Context, backend.Scope, resource.KeyPairQuery) (resource.Page[resource.KeyPair], error) {
	return resource.Page[resource.KeyPair]{}, errors.New("unused")
}

func (foreignCompute) CreateSnapshot(context.Context, backend.Mutation, resource.CreateSnapshotRequest) (resource.Accepted[resource.Snapshot], error) {
	return resource.Accepted[resource.Snapshot]{}, errors.New("unused")
}

func (foreignCompute) DeleteSnapshot(context.Context, backend.Mutation, resource.DeleteSnapshotRequest) (resource.Accepted[resource.Snapshot], error) {
	return resource.Accepted[resource.Snapshot]{}, errors.New("unused")
}

func (foreignCompute) DescribeSnapshots(context.Context, backend.Scope, resource.SnapshotQuery) (resource.Page[resource.Snapshot], error) {
	return resource.Page[resource.Snapshot]{}, errors.New("unused")
}

func (f foreignCompute) GetOperation(context.Context, backend.Scope, resource.OperationID) (resource.Operation, error) {
	if f.op.ID.IsZero() {
		return resource.Operation{}, errors.New("unused")
	}
	return f.op, nil
}

func TestForeignObjectListingIsInternal(t *testing.T) {
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	bucket, err := resource.Parse[resource.BucketName]("build-logs")
	if err != nil {
		t.Fatal(err)
	}
	key, err := resource.Parse[resource.ObjectKey]("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	stub := foreignObjects{obj: resource.Object{Bucket: bucket, Key: key, OwnerID: other}}
	svc := New(Config{Backends: backend.Set{Storage: stub}})
	_, err = svc.ListObjects(context.Background(), caller(t), resource.ObjectQuery{Bucket: bucket})
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("got %v", err)
	}
}

type foreignObjects struct {
	backend.Storage
	obj resource.Object
}

func (f foreignObjects) ListObjects(context.Context, backend.Scope, resource.ObjectQuery) (resource.ObjectListing, error) {
	return resource.ObjectListing{Objects: []resource.Object{f.obj}}, nil
}

func TestZeroAccountIsUnauthenticated(t *testing.T) {
	svc := New(Config{Backends: backend.Set{Compute: foreignCompute{}}})
	_, err := svc.RunInstances(context.Background(), resource.Caller{}, token(t, "launch-web-1"), runReq(t))
	if resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Fatalf("run: %v", err)
	}
	opID, _ := resource.NewOperationID(resource.ServiceCompute, "5f0c2a9e1b7d4c3a")
	if _, err := svc.GetOperation(context.Background(), resource.Caller{}, opID); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Fatalf("poll: %v", err)
	}
}

func TestForeignOperationIsInternal(t *testing.T) {
	id, _ := resource.Parse[resource.InstanceID]("i-0123456789abcdef0")
	other, _ := resource.Parse[resource.AccountID]("210987654321")
	opID, _ := resource.NewOperationID(resource.ServiceCompute, "5f0c2a9e1b7d4c3a")
	stub := foreignCompute{op: resource.Operation{
		ID: opID, Action: resource.ActionRunInstances, State: resource.OperationSucceeded,
		OwnerID: other, Targets: []resource.Ref{id.Ref()},
	}}
	svc := New(Config{Backends: backend.Set{Compute: stub}})
	_, err := svc.GetOperation(context.Background(), caller(t), opID)
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("got %v", err)
	}
	wrong := stub
	wrong.op.OwnerID = caller(t).Account
	wrong.op.ID, _ = resource.NewOperationID(resource.ServiceCompute, "aaaaaaaaaaaaaaaa")
	svc = New(Config{Backends: backend.Set{Compute: wrong}})
	_, err = svc.GetOperation(context.Background(), caller(t), opID)
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("id mismatch: %v", err)
	}
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
