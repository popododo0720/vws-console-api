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
func Run(t *testing.T, newSet Harness, caps resource.RegionCapabilities) {
	t.Helper()
	if err := caps.Validate(); err != nil {
		t.Fatal(err)
	}
	t.Run("Capabilities", func(t *testing.T) { capabilityContract(t, newSet(), caps) })
	t.Run("Reboot", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionRebootInstances, resource.ActionCreateSubnet,
				resource.ActionRunInstances, resource.ActionStopInstances,
			},
			[]resource.ReadAction{resource.ReadDescribeInstances})
		Reboot(t, newSet)
	})
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
	var subnet resource.SubnetID
	var stopped resource.InstanceID
	t.Run("Subnet", func(t *testing.T) {
		requireCapabilities(t, caps, []resource.Action{resource.ActionCreateSubnet}, []resource.ReadAction{})
		subnet = contractSubnet(ctx, t, set, account)
	})
	t.Run("NetworkTags", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionCreateSubnet,
				resource.ActionCreateVpc,
				resource.ActionCreateTags,
				resource.ActionDeleteTags,
			},
			[]resource.ReadAction{
				resource.ReadDescribeSubnets,
				resource.ReadDescribeVpcs,
			})
		networkTags(t, set, account)
	})
	t.Run("VolumeTags", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionCreateVolume,
				resource.ActionCreateTags,
				resource.ActionDeleteTags,
			},
			[]resource.ReadAction{
				resource.ReadDescribeVolumes,
			})
		volumeTags(t, set, account)
	})
	t.Run("Lifecycle", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionCreateSubnet,
				resource.ActionRunInstances,
				resource.ActionStopInstances,
			},
			[]resource.ReadAction{
				resource.ReadDescribeInstances,
				resource.ReadDescribeSubnets,
				resource.ReadDescribeVolumes,
			})
		stopped = contractLifecycle(ctx, t, set, account, other, img, subnet, caps)
	})
	t.Run("Objects", func(t *testing.T) { contractObjects(ctx, t, set, account, other) })
	t.Run("EC2", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionAttachVolume,
				resource.ActionAuthorizeSecurityGroupIngress,
				resource.ActionCreateKeyPair,
				resource.ActionCreateSecurityGroup,
				resource.ActionCreateSnapshot,
				resource.ActionCreateSubnet,
				resource.ActionCreateVolume,
				resource.ActionCreateVpc,
				resource.ActionDeleteKeyPair,
				resource.ActionDeleteSecurityGroup,
				resource.ActionDeleteSnapshot,
				resource.ActionDeleteSubnet,
				resource.ActionDeleteVolume,
				resource.ActionDeleteVpc,
				resource.ActionDetachVolume,
				resource.ActionModifyVolume,
				resource.ActionRevokeSecurityGroupIngress,
				resource.ActionRunInstances,
				resource.ActionStartInstances,
				resource.ActionStopInstances,
				resource.ActionTerminateInstances,
			},
			[]resource.ReadAction{
				resource.ReadDescribeImages,
				resource.ReadDescribeInstances,
				resource.ReadDescribeKeyPairs,
				resource.ReadDescribeSecurityGroups,
				resource.ReadDescribeSnapshots,
				resource.ReadDescribeSubnets,
				resource.ReadDescribeVolumes,
				resource.ReadDescribeVpcs,
			})
		exerciseEC2(ctx, t, set, account, stopped, caps)
	})
	t.Run("KeyLaunch", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionCreateKeyPair,
				resource.ActionCreateSubnet,
				resource.ActionRunInstances,
			},
			[]resource.ReadAction{
				resource.ReadDescribeInstances,
				resource.ReadDescribeKeyPairs,
			})
		exerciseKeyLaunch(ctx, t, set, account, subnet, img)
	})
	t.Run("KeyRetry", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionCreateKeyPair,
			},
			[]resource.ReadAction{
				resource.ReadDescribeKeyPairs,
			})
		exerciseKeyRetry(ctx, t, set, account)
	})
	t.Run("RootDevice", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionCreateSubnet,
				resource.ActionRunInstances,
			},
			[]resource.ReadAction{
				resource.ReadDescribeInstances,
				resource.ReadDescribeVolumes,
			})
		exerciseRootDevice(ctx, t, set, account, subnet, img)
	})
	t.Run("RootVolumeType", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionCreateSubnet,
				resource.ActionRunInstances,
			},
			[]resource.ReadAction{
				resource.ReadDescribeInstances,
				resource.ReadDescribeVolumes,
			})
		exerciseRootVolumeType(ctx, t, set, account, subnet, img)
	})
	t.Run("RootVolumeSize", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionCreateSubnet,
				resource.ActionRunInstances,
			},
			[]resource.ReadAction{
				resource.ReadDescribeInstances,
				resource.ReadDescribeVolumes,
			})
		exerciseRootVolumeSize(ctx, t, set, account, subnet, img)
	})
	t.Run("RootDeleteOnTermination", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionCreateSubnet,
				resource.ActionDeleteVolume,
				resource.ActionRunInstances,
				resource.ActionTerminateInstances,
			},
			[]resource.ReadAction{
				resource.ReadDescribeInstances,
				resource.ReadDescribeVolumes,
			})

		exerciseRootDeleteOnTermination(ctx, t, set, account, subnet, img)
	})
	t.Run("LaunchExtraVolumes", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionCreateSubnet,
				resource.ActionDeleteVolume,
				resource.ActionDetachVolume,
				resource.ActionRunInstances,
				resource.ActionTerminateInstances,
			},
			[]resource.ReadAction{
				resource.ReadDescribeInstances,
				resource.ReadDescribeVolumes,
			})
		exerciseLaunchExtraVolumes(ctx, t, set, account, subnet, img)
	})
	t.Run("TerminateRelease", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionAllocateAddress,
				resource.ActionAssociateAddress,
				resource.ActionCreateSubnet,
				resource.ActionReleaseAddress,
				resource.ActionRunInstances,
				resource.ActionTerminateInstances,
			},
			[]resource.ReadAction{
				resource.ReadDescribeAddresses,
				resource.ReadDescribeInstances,
				resource.ReadDescribeVolumes,
			})
		exerciseTerminateRelease(ctx, t, set, account, subnet, img)
	})
	t.Run("VolumeTypes", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionCreateVolume,
				resource.ActionDeleteVolume,
				resource.ActionModifyVolume,
			},
			[]resource.ReadAction{
				resource.ReadDescribeVolumes,
			})
		exerciseVolumeTypes(ctx, t, set, account)
	})
	t.Run("RegisterImage", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionCreateSnapshot,
				resource.ActionCreateVolume,
				resource.ActionRegisterImage,
			},
			[]resource.ReadAction{
				resource.ReadDescribeImages,
			})
		exerciseRegisterImage(ctx, t, set, account, other)
	})
}

func contractSubnet(ctx context.Context, t *testing.T, set backend.Set, account resource.AccountID) resource.SubnetID {
	t.Helper()
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
	return created.Items[0].ID
}

func contractLifecycle(
	ctx context.Context, t *testing.T, set backend.Set, account, other resource.AccountID,
	img resource.ImageID, subnet resource.SubnetID, caps resource.RegionCapabilities,
) resource.InstanceID {
	t.Helper()
	exerciseImageRegion(ctx, t, set, account, subnet)
	req := resource.RunInstancesRequest{
		ImageID: img, InstanceType: "vws.small", SubnetID: subnet, Count: 1,
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
		IDs: []resource.SubnetID{subnet}, Page: resource.PageRequest{Size: 50},
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
	t.Run("InstanceTags", func(t *testing.T) {
		requireCapabilities(t, caps,
			[]resource.Action{
				resource.ActionCreateTags,
				resource.ActionDeleteTags,
			},
			[]resource.ReadAction{
				resource.ReadDescribeInstances,
			})
		tagged, err := set.Compute.CreateTags(ctx,
			backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-tags", Fingerprint: "fp-tags"},
			resource.CreateTagsRequest{
				IDs: []resource.InstanceID{first.Items[0].ID}, Tags: unlabelableTags("web-2"),
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
		wantTags := unlabelableTags("web-2")
		wantTags["env"] = "dev"
		if got := retagged.Items[0].Tags; !maps.Equal(got, wantTags) {
			t.Fatalf("tags after CreateTags\n got %q\nwant %q", got, wantTags)
		}
		if retagged.Items[0].State != resource.InstanceRunning {
			t.Fatalf("CreateTags changed the state to %s", retagged.Items[0].State)
		}
		untagMut := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-untag", Fingerprint: "fp-untag"}
		untagged, err := set.Compute.DeleteTags(ctx, untagMut, resource.DeleteTagsRequest{
			IDs: []resource.InstanceID{first.Items[0].ID}, Tags: []resource.TagSelector{{Key: "Cost Center"}},
		})
		if err != nil || untagged.Operation.Action != resource.ActionDeleteTags {
			t.Fatalf("delete tags: %v %+v", err, untagged)
		}
		untaggedPage, err := set.Compute.DescribeInstances(ctx, backend.Scope{Account: account}, resource.InstanceQuery{
			IDs: []resource.InstanceID{first.Items[0].ID}, Page: resource.PageRequest{Size: 50},
		})
		if err != nil {
			t.Fatal(err)
		}
		delete(wantTags, "Cost Center")
		if got := untaggedPage.Items[0].Tags; !maps.Equal(got, wantTags) {
			t.Fatalf("tags after DeleteTags\n got %q\nwant %q", got, wantTags)
		}
	})
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

	return first.Items[0].ID
}

func contractObjects(ctx context.Context, t *testing.T, set backend.Set, account, other resource.AccountID) {
	t.Helper()
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

// unlabelableTags are EC2-valid tags that a resource API label cannot hold
// as they are: a key with uppercase or punctuation, a key in the vws- label
// space, and values over 63 bytes (#93).
func unlabelableTags(name string) map[string]string {
	return map[string]string{
		"Name":                   name,
		"Cost Center":            "42",
		"vws-looks-internal":     "user value",
		"aws:cloudformation:id":  "a<b>&c",
		"long":                   strings.Repeat("v", 256),
		strings.Repeat("K", 128): strings.Repeat("€", 85),
	}
}

// networkTags checks that VPC and subnet tags survive create, describe, and a
// CreateTags merge, including tags that are not valid backend labels.
func networkTags(t *testing.T, set backend.Set, account resource.AccountID) {
	t.Helper()
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	odd := unlabelableTags("net-1")
	odd["env"] = "dev"
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
	want := maps.Clone(odd)
	maps.Copy(want, add)
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
	prod, exact := "prod", "42"
	uv, err := set.Network.UntagVpcs(ctx, backend.Mutation{Scope: scope, Key: "k-untagvpc", Fingerprint: "fp-untagvpc"},
		resource.UntagVpcsRequest{IDs: []resource.VpcID{vpcID}, Tags: []resource.TagSelector{
			{Key: "Owner Team"}, {Key: "env", Value: &prod}, {Key: "Cost Center", Value: &exact}, {Key: "absent"},
		}})
	if err != nil || uv.Operation.Action != resource.ActionDeleteTags {
		t.Fatalf("UntagVpcs: %v %+v", err, uv.Operation)
	}
	kept := maps.Clone(want)
	delete(kept, "Owner Team")
	delete(kept, "Cost Center")
	if got := vpcTags(); !maps.Equal(got, kept) {
		t.Fatalf("vpc tags after DeleteTags %v, want %v", got, kept)
	}
	us, err := set.Network.UntagSubnets(ctx, backend.Mutation{Scope: scope, Key: "k-untagsub", Fingerprint: "fp-untagsub"},
		resource.UntagSubnetsRequest{IDs: []resource.SubnetID{subID}})
	if err != nil || us.Operation.Action != resource.ActionDeleteTags {
		t.Fatalf("UntagSubnets: %v %+v", err, us.Operation)
	}
	// DeleteTags with no tags deletes every tag except the aws: ones.
	keepAWS := map[string]string{"aws:cloudformation:id": want["aws:cloudformation:id"]}
	if got := subTags(); !maps.Equal(got, keepAWS) {
		t.Fatalf("subnet tags after DeleteTags with no tags %v, want %v", got, keepAWS)
	}
	missing := backend.Mutation{Scope: scope, Key: "k-untagvpc-missing", Fingerprint: "fp-untagvpc-missing"}
	_, err = set.Network.UntagVpcs(ctx, missing, resource.UntagVpcsRequest{IDs: []resource.VpcID{vpcID, missingVpc(t)}})
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("UntagVpcs on a missing VPC: %v", err)
	}
	if got := vpcTags(); !maps.Equal(got, kept) {
		t.Fatalf("a failed DeleteTags changed the vpc tags to %v", got)
	}
}

func missingVpc(t *testing.T) resource.VpcID {
	t.Helper()
	id, err := resource.Parse[resource.VpcID]("vpc-0fffffffffffffff0")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// volumeTags checks tag merges and deletes, and that an unknown volume id
// changes no volume.
func volumeTags(t *testing.T, set backend.Set, account resource.AccountID) {
	t.Helper()
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	odd := map[string]string{"Name": "data-1", "Cost Center": "42", "env": "dev", "aws:stack": "system"}
	vol, err := set.Compute.CreateVolume(ctx, backend.Mutation{Scope: scope, Key: "k-tvol", Fingerprint: "fp-tvol"},
		resource.CreateVolumeRequest{SizeGiB: 8, Zone: resource.ZoneName, Type: resource.VolumeGP2, Tags: odd})
	if err != nil {
		t.Fatal(err)
	}
	volID := vol.Items[0].ID
	if !maps.Equal(vol.Items[0].Tags, odd) {
		t.Fatalf("accepted volume tags %v", vol.Items[0].Tags)
	}
	volTags := func() map[string]string {
		page, err := set.Compute.DescribeVolumes(ctx, scope,
			resource.VolumeQuery{IDs: []resource.VolumeID{volID}, Page: resource.PageRequest{Size: 5}})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("describe volume: %v %+v", err, page.Items)
		}
		return page.Items[0].Tags
	}
	if got := volTags(); !maps.Equal(got, odd) {
		t.Fatalf("volume tags %v", got)
	}
	add := map[string]string{"Name": "data-2", "Owner Team": "SRE"}
	want := map[string]string{
		"Name": "data-2", "Cost Center": "42", "env": "dev", "Owner Team": "SRE", "aws:stack": "system",
	}
	tv, err := set.Compute.TagVolumes(ctx, backend.Mutation{Scope: scope, Key: "k-tagvol", Fingerprint: "fp-tagvol"},
		resource.TagVolumesRequest{IDs: []resource.VolumeID{volID}, Tags: add})
	if err != nil || tv.Operation.Action != resource.ActionCreateTags ||
		len(tv.Items) != 1 || !maps.Equal(tv.Items[0].Tags, want) {
		t.Fatalf("TagVolumes: %v %+v", err, tv)
	}
	if got := volTags(); !maps.Equal(got, want) {
		t.Fatalf("volume tags after CreateTags %v", got)
	}
	missing, err := resource.Parse[resource.VolumeID]("vol-0fffffffffffffff0")
	if err != nil {
		t.Fatal(err)
	}
	miss := backend.Mutation{Scope: scope, Key: "k-tagvol-miss", Fingerprint: "fp-tagvol-miss"}
	_, err = set.Compute.TagVolumes(ctx, miss,
		resource.TagVolumesRequest{IDs: []resource.VolumeID{volID, missing}, Tags: map[string]string{"stray": "x"}})
	var re *resource.Error
	if !errors.As(err, &re) || re.Code != resource.CodeNotFound {
		t.Fatalf("TagVolumes with a missing volume: %v", err)
	}
	if got := volTags(); !maps.Equal(got, want) {
		t.Fatalf("a refused CreateTags changed the volume: %v", got)
	}
	del := backend.Mutation{Scope: scope, Key: "k-untagvol", Fingerprint: "fp-untagvol"}
	prod, exact := "prod", "42"
	req := resource.UntagVolumesRequest{IDs: []resource.VolumeID{volID}, Tags: []resource.TagSelector{
		{Key: "Name"}, {Key: "env", Value: &prod}, {Key: "Cost Center", Value: &exact}, {Key: "absent"},
	}}
	untagged, err := set.Compute.UntagVolumes(ctx, del, req)
	kept := map[string]string{"env": "dev", "Owner Team": "SRE", "aws:stack": "system"}
	if err != nil || untagged.Operation.Action != resource.ActionDeleteTags ||
		len(untagged.Items) != 1 || !maps.Equal(untagged.Items[0].Tags, kept) {
		t.Fatalf("UntagVolumes: %v %+v", err, untagged)
	}
	if got := volTags(); !maps.Equal(got, kept) {
		t.Fatalf("volume tags after DeleteTags: %v", got)
	}
	repeated, err := set.Compute.UntagVolumes(ctx, del, req)
	if err != nil || repeated.Operation.ID != untagged.Operation.ID {
		t.Fatalf("repeated UntagVolumes: %v %+v", err, repeated)
	}
	_, err = set.Compute.UntagVolumes(ctx,
		backend.Mutation{Scope: scope, Key: "k-untagvol-miss", Fingerprint: "fp-untagvol-miss"},
		resource.UntagVolumesRequest{IDs: []resource.VolumeID{volID, missing}})
	if !errors.As(err, &re) || re.Code != resource.CodeNotFound || re.Kind != resource.KindVolume {
		t.Fatalf("UntagVolumes with a missing volume: %v", err)
	}
	if got := volTags(); !maps.Equal(got, kept) {
		t.Fatalf("a refused DeleteTags changed the volume: %v", got)
	}
	_, err = set.Compute.UntagVolumes(ctx,
		backend.Mutation{Scope: scope, Key: "k-untagvol-all", Fingerprint: "fp-untagvol-all"},
		resource.UntagVolumesRequest{IDs: []resource.VolumeID{volID}})
	if err != nil {
		t.Fatal(err)
	}
	if got := volTags(); !maps.Equal(got, map[string]string{"aws:stack": "system"}) {
		t.Fatalf("volume tags after deleting all: %v", got)
	}
}
