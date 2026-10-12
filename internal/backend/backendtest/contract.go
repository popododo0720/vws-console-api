// Package backendtest is the contract every backend set must pass.
package backendtest

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Harness builds a fresh backend set for one test.
type Harness func() backend.Set

// Run checks idempotency, tenancy, and the instance lifecycle.
func Run(t *testing.T, newSet Harness) {
	t.Helper()
	ctx := context.Background()
	set := newSet()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	img, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	subReq := resource.CreateSubnetRequest{Cidr: "10.2.0.0/24"}
	sm := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k3", Fingerprint: "fp3"}
	created, err := set.Network.CreateSubnet(ctx, sm, subReq)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := set.Network.CreateSubnet(ctx, sm, subReq)
	if err != nil || replay.Items[0].ID != created.Items[0].ID {
		t.Fatal("subnet retry")
	}
	if _, err := set.Network.GetOperation(ctx, backend.Scope{Account: account}, created.Operation.ID); err != nil {
		t.Fatal(err)
	}
	req := resource.RunInstancesRequest{ImageID: img, InstanceType: "vws.small", SubnetID: created.Items[0].ID, Count: 1}
	m := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k1", Fingerprint: "fp1"}

	first, err := set.Compute.RunInstances(ctx, m, req)
	if err != nil {
		t.Fatal(err)
	}
	if first.Operation.OwnerID != account {
		t.Fatalf("operation owner %s", first.Operation.OwnerID)
	}
	if first.Operation.State != resource.OperationRunning {
		t.Fatalf("state %s", first.Operation.State)
	}
	if first.Items[0].OwnerID != account || first.Items[0].State != resource.InstancePending {
		t.Fatalf("item %+v", first.Items[0])
	}
	again, err := set.Compute.RunInstances(ctx, m, req)
	if err != nil {
		t.Fatal(err)
	}
	if again.Operation.ID != first.Operation.ID || again.Items[0].ID != first.Items[0].ID {
		t.Fatal("retry changed the resource")
	}
	clash := m
	clash.Fingerprint = "other"
	if _, err := set.Compute.RunInstances(ctx, clash, req); resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
		t.Fatalf("mismatch: %v", err)
	}

	op, err := set.Compute.GetOperation(ctx, backend.Scope{Account: account}, first.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != resource.OperationSucceeded {
		t.Fatalf("operation stayed %s", op.State)
	}
	page, err := set.Compute.DescribeInstances(ctx, backend.Scope{Account: account}, resource.InstanceQuery{
		IDs:  []resource.InstanceID{first.Items[0].ID},
		Page: resource.PageRequest{Size: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.Items[0].State != resource.InstanceRunning {
		t.Fatalf("state %s", page.Items[0].State)
	}
	filtered, err := set.Compute.DescribeInstances(ctx, backend.Scope{Account: account}, resource.InstanceQuery{
		IDs:    []resource.InstanceID{first.Items[0].ID},
		States: []resource.InstanceState{resource.InstancePending},
		Page:   resource.PageRequest{Size: 50},
	})
	if err != nil {
		t.Fatalf("state filter: %v", err)
	}
	if len(filtered.Items) != 0 {
		t.Fatalf("state filter returned %+v", filtered.Items)
	}
	if _, err := set.Compute.DescribeInstances(ctx, backend.Scope{Account: account}, resource.InstanceQuery{
		Page: resource.PageRequest{Size: 50, Token: "missing-page"},
	}); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("page token: %v", err)
	}
	if _, err := set.Compute.DescribeInstances(ctx, backend.Scope{Account: other}, resource.InstanceQuery{
		IDs:  []resource.InstanceID{first.Items[0].ID},
		Page: resource.PageRequest{Size: 50},
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("other account: %v", err)
	}

	stop := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k2", Fingerprint: "fp2"}
	change, err := set.Compute.StopInstances(ctx, stop, resource.StopInstancesRequest{IDs: []resource.InstanceID{first.Items[0].ID}})
	if err != nil {
		t.Fatal(err)
	}
	if change.Items[0].Current != resource.InstanceStopping {
		t.Fatalf("stop current %s", change.Items[0].Current)
	}
	if _, err := set.Compute.GetOperation(ctx, backend.Scope{Account: account}, change.Operation.ID); err != nil {
		t.Fatal(err)
	}
	stopped, err := set.Compute.DescribeInstances(ctx, backend.Scope{Account: account}, resource.InstanceQuery{
		IDs:  []resource.InstanceID{first.Items[0].ID},
		Page: resource.PageRequest{Size: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Items[0].State != resource.InstanceStopped {
		t.Fatalf("stopped %s", stopped.Items[0].State)
	}

	pairReq := req
	pairReq.Count = 2
	pair, err := set.Compute.RunInstances(ctx, backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-pair", Fingerprint: "fp-pair"}, pairReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.GetOperation(ctx, backend.Scope{Account: account}, pair.Operation.ID); err != nil {
		t.Fatal(err)
	}
	missing, err := resource.Parse[resource.InstanceID]("i-01234567")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.StopInstances(ctx, backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-partial", Fingerprint: "fp-partial"}, resource.StopInstancesRequest{
		IDs: []resource.InstanceID{pair.Items[0].ID, missing},
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("partial stop: %v", err)
	}
	left, err := set.Compute.DescribeInstances(ctx, backend.Scope{Account: account}, resource.InstanceQuery{
		IDs:  []resource.InstanceID{pair.Items[0].ID, pair.Items[1].ID},
		Page: resource.PageRequest{Size: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(left.Items) != 2 || left.Items[0].State != resource.InstanceRunning || left.Items[1].State != resource.InstanceRunning {
		t.Fatalf("partial stop applied %+v", left.Items)
	}

	name, err := resource.Parse[resource.BucketName]("build-logs")
	if err != nil {
		t.Fatal(err)
	}
	bucket, err := set.Storage.CreateBucket(ctx, backend.Scope{Account: account}, name)
	if err != nil {
		t.Fatal(err)
	}
	againBucket, err := set.Storage.CreateBucket(ctx, backend.Scope{Account: account}, name)
	if err != nil || againBucket.Name != bucket.Name {
		t.Fatal(err)
	}
	if _, err := set.Storage.CreateBucket(ctx, backend.Scope{Account: other}, name); resource.CodeOf(err) != resource.CodeAlreadyExists {
		t.Fatalf("bucket owner: %v", err)
	}
	key, err := resource.Parse[resource.ObjectKey]("a/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	body := strings.NewReader("hello")
	obj, err := set.Storage.PutObject(ctx, backend.Scope{Account: account}, resource.PutObjectRequest{
		Bucket: name, Key: key, ContentType: "text/plain", Size: 5,
	}, body)
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size != 5 || obj.OwnerID != account {
		t.Fatalf("object %+v", obj)
	}
	replaced, err := set.Storage.PutObject(ctx, backend.Scope{Account: account}, resource.PutObjectRequest{
		Bucket: name, Key: key, ContentType: "text/plain", Size: 6,
	}, strings.NewReader("hello!"))
	if err != nil || replaced.Size != 6 || replaced.ETag == obj.ETag {
		t.Fatalf("overwrite: %v %+v", err, replaced)
	}
	meta, rc, err := set.Storage.GetObject(ctx, backend.Scope{Account: account}, resource.GetObjectRequest{Bucket: name, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	if meta.ETag != replaced.ETag || meta.Size != replaced.Size {
		t.Fatalf("etag %s size %d", meta.ETag, meta.Size)
	}
	if got, err := io.ReadAll(rc); err != nil || string(got) != "hello!" {
		t.Fatalf("body %q: %v", got, err)
	}
	if _, err := set.Storage.PutObject(ctx, backend.Scope{Account: account}, resource.PutObjectRequest{
		Bucket: name, Key: key, Size: 1,
	}, strings.NewReader("hello")); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("size mismatch: %v", err)
	}
	bigKey, err := resource.Parse[resource.ObjectKey]("big.bin")
	if err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte{'x'}, resource.MaxObjectBytes)
	stored, err := set.Storage.PutObject(ctx, backend.Scope{Account: account}, resource.PutObjectRequest{
		Bucket: name, Key: bigKey, Size: int64(len(big)),
	}, bytes.NewReader(big))
	if err != nil || stored.Size != int64(len(big)) {
		t.Fatalf("cap: %v %+v", err, stored)
	}
	_, err = set.Storage.PutObject(ctx, backend.Scope{Account: account}, resource.PutObjectRequest{
		Bucket: name, Key: bigKey, Size: int64(len(big) + 1),
	}, bytes.NewReader(append(big, 'y')))
	if resource.CodeOf(err) != resource.CodePayloadTooLarge {
		t.Fatalf("over cap: %v", err)
	}
	exerciseObjectList(ctx, t, set, account, other)
	exerciseEC2(ctx, t, set, account, first.Items[0].ID)
}
