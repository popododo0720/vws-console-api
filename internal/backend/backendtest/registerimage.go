package backendtest

import (
	"context"
	"errors"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// exerciseRegisterImage checks that an image registered from a completed
// snapshot reads back as an EC2 image, that a retry returns the first
// registration, and that another account's snapshot is not found.
func exerciseRegisterImage(ctx context.Context, t *testing.T, set backend.Set, account, other resource.AccountID) {
	t.Helper()
	scope := backend.Scope{Account: account}
	vol, err := set.Compute.CreateVolume(ctx, backend.Mutation{Scope: scope, Key: "k-img-vol", Fingerprint: "fp-img-vol"},
		resource.CreateVolumeRequest{SizeGiB: 12, Zone: resource.ZoneName, Type: resource.VolumeGP2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, vol.Operation.ID); err != nil {
		t.Fatal(err)
	}
	snap, err := set.Compute.CreateSnapshot(ctx,
		backend.Mutation{Scope: scope, Key: "k-img-snap", Fingerprint: "fp-img-snap"},
		resource.CreateSnapshotRequest{VolumeID: vol.Items[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, snap.Operation.ID); err != nil {
		t.Fatal(err)
	}
	req := resource.RegisterImageRequest{Name: "web base (2026)", Description: "nightly", SnapshotID: snap.Items[0].ID}
	mut := backend.Mutation{Scope: scope, Key: "k-register", Fingerprint: "fp-register"}
	acc, err := set.Compute.RegisterImage(ctx, mut, req)
	if err != nil {
		t.Fatalf("register image: %v", err)
	}
	img := acc.Items[0]
	if img.OwnerID != account || img.Name != req.Name || img.State != resource.ImagePending ||
		img.SizeGiB != 12 || acc.Operation.Action != resource.ActionRegisterImage {
		t.Fatalf("registered image: %+v %s", img, acc.Operation.Action)
	}
	op, err := set.Compute.GetOperation(ctx, scope, acc.Operation.ID)
	if err != nil || op.Action != resource.ActionRegisterImage || len(op.Targets) != 1 || op.Targets[0] != img.ID.Ref() {
		t.Fatalf("register operation: %v %+v", err, op)
	}
	got, err := set.Compute.DescribeImages(ctx, scope, resource.ImageQuery{
		IDs: []resource.ImageID{img.ID}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(got.Items) != 1 || got.Items[0].Name != req.Name || got.Items[0].Description != "nightly" ||
		got.Items[0].State != resource.ImageAvailable || got.Items[0].SizeGiB != 12 || got.Items[0].OwnerID != account {
		t.Fatalf("describe registered image: %v %+v", err, got.Items)
	}
	listed, err := set.Compute.DescribeImages(ctx, scope, resource.ImageQuery{Page: resource.PageRequest{Size: 50}})
	if err != nil || !hasImage(listed.Items, img.ID) {
		t.Fatalf("list images: %v %+v", err, listed.Items)
	}
	retried, err := set.Compute.RegisterImage(ctx, mut, req)
	if err != nil || retried.Items[0].ID != img.ID || retried.Operation.ID != acc.Operation.ID {
		t.Fatalf("register retry: %v %+v", err, retried)
	}

	_, err = set.Compute.RegisterImage(ctx, backend.Mutation{
		Scope: backend.Scope{Account: other}, Key: "k-register-foreign", Fingerprint: "fp-register-foreign",
	}, req)
	var refused *resource.Error
	if !errors.As(err, &refused) || refused.Code != resource.CodeNotFound || refused.Kind != resource.KindSnapshot ||
		refused.ID != snap.Items[0].ID.String() {
		t.Fatalf("register from another account's snapshot: %v", err)
	}
	if theirs, err := set.Compute.DescribeImages(ctx, backend.Scope{Account: other}, resource.ImageQuery{
		Page: resource.PageRequest{Size: 50},
	}); err != nil || hasImage(theirs.Items, img.ID) {
		t.Fatalf("another account lists the image: %v %+v", err, theirs.Items)
	}
}

func hasImage(items []resource.Image, id resource.ImageID) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}
