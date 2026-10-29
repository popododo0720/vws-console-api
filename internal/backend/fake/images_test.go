package fake

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestDescribeImagesListsPublicButNotForeignPrivate(t *testing.T) {
	ctx := context.Background()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	own := image(t, "ami-00000000000000001", account, false)
	public := image(t, "ami-00000000000000002", other, true)
	private := image(t, "ami-00000000000000003", other, false)
	duplicate := image(t, "ami-0123456789abcdef0", other, true)
	w := New(Options{Images: []resource.Image{own, public, private, duplicate}})
	scope := backend.Scope{Account: account}
	page, err := w.Set().Compute.DescribeImages(ctx, scope, resource.ImageQuery{Page: resource.PageRequest{Size: 50}})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, img := range page.Items {
		ids[img.ID.String()] = true
		if img.ID == public.ID && !img.Public {
			t.Fatalf("public image %+v", img)
		}
		if img.ID.String() == "ami-0123456789abcdef0" && (img.OwnerID != account || img.Public) {
			t.Fatalf("catalog duplicate %+v", img)
		}
	}
	if !ids[own.ID.String()] || !ids[public.ID.String()] || ids[private.ID.String()] {
		t.Fatalf("images %v", ids)
	}
	if len(ids) != 3 {
		t.Fatalf("images %v, want own, public and the catalog", ids)
	}
	mine, err := w.Set().Compute.DescribeImages(ctx, scope, resource.ImageQuery{
		Owner: account, Page: resource.PageRequest{Size: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, img := range mine.Items {
		if img.OwnerID != account {
			t.Fatalf("owner filter kept %+v", img)
		}
	}
	if len(mine.Items) != 2 {
		t.Fatalf("owner filter %+v, want own image and the catalog", mine.Items)
	}
	if _, err := w.Set().Compute.DescribeImages(ctx, scope, resource.ImageQuery{
		IDs: []resource.ImageID{private.ID}, Page: resource.PageRequest{Size: 50},
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("private foreign image: %v", err)
	}
}

func TestRunInstancesLaunchesASeededImage(t *testing.T) {
	ctx := context.Background()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	own := image(t, "ami-00000000000000011", account, false)
	public := image(t, "ami-00000000000000012", other, true)
	private := image(t, "ami-00000000000000013", other, false)
	w := New(Options{Images: []resource.Image{own, public, private}})
	set := w.Set()
	scope := backend.Scope{Account: account}
	sub, err := set.Network.CreateSubnet(ctx, backend.Mutation{
		Scope: scope, Key: "sub", Fingerprint: "sub",
	}, resource.CreateSubnetRequest{Cidr: "10.9.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Network.GetOperation(ctx, scope, sub.Operation.ID); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		img    resource.Image
		launch bool
	}{
		{name: "own", img: own, launch: true},
		{name: "public", img: public, launch: true},
		{name: "foreign-private", img: private},
	} {
		t.Run(tt.name, func(t *testing.T) {
			acc, err := set.Compute.RunInstances(ctx, backend.Mutation{
				Scope: scope, Key: "run-" + tt.name, Fingerprint: "run",
			}, resource.RunInstancesRequest{
				ImageID: tt.img.ID, InstanceType: "vws.small", SubnetID: sub.Items[0].ID, Count: 1,
			})
			if !tt.launch {
				got := resource.AsError(err)
				if got == nil || got.Code != resource.CodeNotFound || got.Kind != resource.KindImage {
					t.Fatalf("foreign private image: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(acc.Items) != 1 || acc.Items[0].ImageID != tt.img.ID {
				t.Fatalf("launch of %s: %+v", tt.img.ID, acc.Items)
			}
		})
	}
}

func image(t *testing.T, id string, owner resource.AccountID, public bool) resource.Image {
	t.Helper()
	parsed, err := resource.Parse[resource.ImageID](id)
	if err != nil {
		t.Fatal(err)
	}
	return resource.Image{ID: parsed, OwnerID: owner, Name: id, State: "available", Public: public}
}
