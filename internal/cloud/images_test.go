package cloud

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// imageList is a compute page under test. Every other method stays unused.
type imageList struct {
	foreignCompute
	page resource.Page[resource.Image]
}

func (f imageList) DescribeImages(
	context.Context, backend.Scope, resource.ImageQuery,
) (resource.Page[resource.Image], error) {
	return f.page, nil
}

func TestDescribeImagesAdmitsAPublicImage(t *testing.T) {
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.Parse[resource.ImageID]("ami-0a1b2c3d4e5f67890")
	if err != nil {
		t.Fatal(err)
	}
	svc := New(Config{Backends: backend.Set{Compute: imageList{page: resource.Page[resource.Image]{
		Items: []resource.Image{{ID: id, OwnerID: other, Name: id.String(), State: "available", Public: true}},
	}}}})
	page, err := svc.DescribeImages(context.Background(), caller(t), resource.ImageQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].OwnerID != other || !page.Items[0].Public {
		t.Fatalf("page %+v", page.Items)
	}
}

func TestDescribeImagesRejectsAForeignPrivateImage(t *testing.T) {
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.Parse[resource.ImageID]("ami-0a1b2c3d4e5f67890")
	if err != nil {
		t.Fatal(err)
	}
	svc := New(Config{Backends: backend.Set{Compute: imageList{page: resource.Page[resource.Image]{
		Items: []resource.Image{{ID: id, OwnerID: other, Name: id.String(), State: "available"}},
	}}}})
	_, err = svc.DescribeImages(context.Background(), caller(t), resource.ImageQuery{})
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("got %v", err)
	}
}
