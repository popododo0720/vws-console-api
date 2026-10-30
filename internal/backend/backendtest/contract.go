// Package backendtest is the contract every backend set must pass.
package backendtest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
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
	exerciseImageRegion(ctx, t, set, account, created.Items[0].ID)
	networkTags(t, set, account)
	req := resource.RunInstancesRequest{
		ImageID: img, InstanceType: "vws.small", SubnetID: created.Items[0].ID, Count: 1,
		Tags: map[string]string{"Name": "web-1", "env": "dev"},
	}
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
	if got := page.Items[0]; got.LaunchTime.IsZero() {
		t.Fatalf("launch time missing: %+v", got)
	}
	subs, err := set.Network.DescribeSubnets(ctx, backend.Scope{Account: account}, resource.SubnetQuery{
		IDs: []resource.SubnetID{created.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || subs.Items[0].Zone != resource.ZoneName {
		t.Fatalf("subnet zone: %v %+v", err, subs.Items)
	}
	if page.Items[0].VpcID != subs.Items[0].VpcID {
		t.Fatalf("instance vpc %q, subnet vpc %q", page.Items[0].VpcID, subs.Items[0].VpcID)
	}
	if got := page.Items[0].Tags; got["Name"] != "web-1" || got["env"] != "dev" || len(got) != 2 {
		t.Fatalf("tags %v, want Name=web-1 env=dev", got)
	}
	tagged, err := set.Compute.CreateTags(ctx, backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-tags", Fingerprint: "fp-tags"}, resource.CreateTagsRequest{
		IDs: []resource.InstanceID{first.Items[0].ID}, Tags: map[string]string{"Name": "web-2", "Cost Center": "42"},
	})
	if err != nil || tagged.Operation.Action != resource.ActionCreateTags {
		t.Fatalf("create tags: %v %+v", err, tagged)
	}
	if _, err := set.Compute.GetOperation(ctx, backend.Scope{Account: account}, tagged.Operation.ID); err != nil {
		t.Fatal(err)
	}
	retagged, err := set.Compute.DescribeInstances(ctx, backend.Scope{Account: account}, resource.InstanceQuery{
		IDs: []resource.InstanceID{first.Items[0].ID}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := retagged.Items[0].Tags; got["Name"] != "web-2" || got["env"] != "dev" || got["Cost Center"] != "42" || len(got) != 3 {
		t.Fatalf("tags after CreateTags %v", got)
	}
	if retagged.Items[0].State != resource.InstanceRunning {
		t.Fatalf("CreateTags changed the state to %s", retagged.Items[0].State)
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
	if _, err := set.Storage.CreateBucket(ctx, backend.Scope{Account: account}, name); err != nil {
		t.Fatal(err)
	}
	if _, err := set.Storage.CreateBucket(ctx, backend.Scope{Account: account}, name); !resource.OwnedByCaller(err) {
		t.Fatalf("owner creates again: %v", err)
	}
	_, err = set.Storage.CreateBucket(ctx, backend.Scope{Account: other}, name)
	if resource.CodeOf(err) != resource.CodeAlreadyExists || resource.OwnedByCaller(err) {
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
	// If-None-Match: * fails on an existing key, even with the same bytes.
	for _, again := range []string{"hello!", "other"} {
		if _, err := set.Storage.PutObject(ctx, backend.Scope{Account: account}, resource.PutObjectRequest{
			Bucket: name, Key: key, Size: int64(len(again)), IfNoneMatch: true,
		}, strings.NewReader(again)); resource.CodeOf(err) != resource.CodeAlreadyExists || resource.AsError(err).Kind != resource.KindObject {
			t.Fatalf("if-none-match %q on an existing key: %v", again, err)
		}
	}
	onceKey, err := resource.Parse[resource.ObjectKey]("once.txt")
	if err != nil {
		t.Fatal(err)
	}
	if once, err := set.Storage.PutObject(ctx, backend.Scope{Account: account}, resource.PutObjectRequest{
		Bucket: name, Key: onceKey, Size: 4, IfNoneMatch: true,
	}, strings.NewReader("once")); err != nil || once.Size != 4 {
		t.Fatalf("if-none-match on a new key: %v %+v", err, once)
	}
	if err := set.Storage.DeleteObject(ctx, backend.Scope{Account: account}, name, onceKey); err != nil {
		t.Fatal(err)
	}
	meta, rc, err := set.Storage.GetObject(ctx, backend.Scope{Account: account}, resource.GetObjectRequest{Bucket: name, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rc.Close(); err != nil {
			t.Error(err)
		}
	}()
	if meta.ETag != replaced.ETag || meta.Size != replaced.Size {
		t.Fatalf("etag %s size %d", meta.ETag, meta.Size)
	}
	// sha256("hello!"), the value S3 returns as ChecksumSHA256.
	const helloBangSHA256 = "ce06092fb948d9ffac7d1a376e404b26b7575bcc11ee05a4615fef4fec3a308b"
	if replaced.SHA256 != helloBangSHA256 || meta.SHA256 != helloBangSHA256 {
		t.Fatalf("sha256 put %q get %q, want %s", replaced.SHA256, meta.SHA256, helloBangSHA256)
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
	exerciseKeyLaunch(ctx, t, set, account, created.Items[0].ID, img)
	exerciseKeyRetry(ctx, t, set, account)
	exerciseRootDevice(ctx, t, set, account, created.Items[0].ID, img)
	exerciseRootVolumeType(ctx, t, set, account, created.Items[0].ID, img)
	exerciseVolumeTypes(ctx, t, set, account)
}

// exerciseImageRegion checks that a launch refuses an image the process cannot
// prove is in this region, and that the refusal creates no volume or instance.
func exerciseImageRegion(
	ctx context.Context, t *testing.T, set backend.Set, account resource.AccountID, subnet resource.SubnetID,
) {
	t.Helper()
	foreign, err := resource.Parse[resource.ImageID]("ami-fedcba9876543210")
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account}
	page := resource.PageRequest{Size: 50}
	beforeVolumes, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{Page: page})
	if err != nil {
		t.Fatal(err)
	}
	beforeInstances, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{Page: page})
	if err != nil {
		t.Fatal(err)
	}
	mut := backend.Mutation{Scope: scope, Key: "k-foreign-image", Fingerprint: "fp-foreign-image"}
	req := resource.RunInstancesRequest{
		ImageID: foreign, InstanceType: "vws.small", SubnetID: subnet, Count: 1,
	}
	_, err = set.Compute.RunInstances(ctx, mut, req)
	var got *resource.Error
	want := "The image id '[" + foreign.String() + "]' does not exist"
	if !errors.As(err, &got) || got.Code != resource.CodeNotFound ||
		got.Kind != resource.KindImage || got.Message != want {
		t.Fatalf("other-region image: %v", err)
	}
	afterVolumes, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{Page: page})
	if err != nil {
		t.Fatal(err)
	}
	afterInstances, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{Page: page})
	if err != nil {
		t.Fatal(err)
	}
	if len(afterVolumes.Items) != len(beforeVolumes.Items) || len(afterInstances.Items) != len(beforeInstances.Items) {
		t.Fatalf("refused launch created volumes %d->%d instances %d->%d",
			len(beforeVolumes.Items), len(afterVolumes.Items), len(beforeInstances.Items), len(afterInstances.Items))
	}
}

// networkTags checks that VPC and subnet tags survive create, describe, and a
// CreateTags merge, including tags that are not valid backend labels.
func networkTags(t *testing.T, set backend.Set, account resource.AccountID) {
	t.Helper()
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	odd := map[string]string{"Name": "net-1", "Cost Center": "42", "env": "dev"}
	vpc, err := set.Network.CreateVpc(ctx, backend.Mutation{Scope: scope, Key: "k-tvpc", Fingerprint: "fp-tvpc"},
		resource.CreateVpcRequest{Cidr: "10.40.0.0/16", Tags: odd})
	if err != nil {
		t.Fatal(err)
	}
	vpcID := vpc.Items[0].ID
	sub, err := set.Network.CreateSubnet(ctx, backend.Mutation{Scope: scope, Key: "k-tsub", Fingerprint: "fp-tsub"},
		resource.CreateSubnetRequest{Cidr: "10.40.1.0/24", VpcID: vpcID, Tags: odd})
	if err != nil {
		t.Fatal(err)
	}
	subID := sub.Items[0].ID
	vpcTags := func() map[string]string {
		page, err := set.Network.DescribeVpcs(ctx, scope, resource.VpcQuery{IDs: []resource.VpcID{vpcID}, Page: resource.PageRequest{Size: 5}})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("describe vpc: %v %+v", err, page.Items)
		}
		return page.Items[0].Tags
	}
	subTags := func() map[string]string {
		page, err := set.Network.DescribeSubnets(ctx, scope, resource.SubnetQuery{IDs: []resource.SubnetID{subID}, Page: resource.PageRequest{Size: 5}})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("describe subnet: %v %+v", err, page.Items)
		}
		return page.Items[0].Tags
	}
	if got := vpcTags(); !maps.Equal(got, odd) {
		t.Fatalf("vpc tags %v", got)
	}
	if got := subTags(); !maps.Equal(got, odd) {
		t.Fatalf("subnet tags %v", got)
	}
	add := map[string]string{"Name": "net-2", "Owner Team": "SRE"}
	want := map[string]string{"Name": "net-2", "Cost Center": "42", "env": "dev", "Owner Team": "SRE"}
	tv, err := set.Network.TagVpcs(ctx, backend.Mutation{Scope: scope, Key: "k-tagvpc", Fingerprint: "fp-tagvpc"},
		resource.TagVpcsRequest{IDs: []resource.VpcID{vpcID}, Tags: add})
	if err != nil || tv.Operation.Action != resource.ActionCreateTags {
		t.Fatalf("TagVpcs: %v %+v", err, tv.Operation)
	}
	ts, err := set.Network.TagSubnets(ctx, backend.Mutation{Scope: scope, Key: "k-tagsub", Fingerprint: "fp-tagsub"},
		resource.TagSubnetsRequest{IDs: []resource.SubnetID{subID}, Tags: add})
	if err != nil || ts.Operation.Action != resource.ActionCreateTags {
		t.Fatalf("TagSubnets: %v %+v", err, ts.Operation)
	}
	if got := vpcTags(); !maps.Equal(got, want) {
		t.Fatalf("vpc tags after CreateTags %v", got)
	}
	if got := subTags(); !maps.Equal(got, want) {
		t.Fatalf("subnet tags after CreateTags %v", got)
	}
	if op, err := set.Network.GetOperation(ctx, scope, tv.Operation.ID); err != nil || op.Action != resource.ActionCreateTags {
		t.Fatalf("tag operation: %v %+v", err, op)
	}
}
