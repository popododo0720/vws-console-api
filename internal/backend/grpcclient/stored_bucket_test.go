package grpcclient

import (
	"testing"
	"time"

	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestStoredReservedBucketNamesAreReadable covers #511: a bucket another path
// wrote with a reserved prefix or suffix is listed and read instead of
// failing the whole conversion as Internal.
func TestStoredReservedBucketNamesAreReadable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	account := mustAccount(t)
	const created = "2026-01-02T03:04:05Z"
	names := []string{"edge-bucket-an", "xn--legacy"}
	buckets := make([]resource.Bucket, 0, len(names))
	for _, name := range names {
		parsed, err := resource.ParseStoredBucketName(name)
		if err != nil {
			t.Fatal(err)
		}
		buckets = append(buckets, resource.Bucket{Name: parsed, OwnerID: account, CreationDate: created})
	}
	world := fake.New(fake.Options{Now: func() time.Time { return now }, Entropy: &fake.Sequence{}, Buckets: buckets})
	set := dialLoopback(t, world, now)()
	ctx := t.Context()
	scope := backend.Scope{Account: account}

	page, err := set.Storage.ListBuckets(ctx, scope, resource.BucketQuery{})
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	got := map[string]bool{}
	for _, bucket := range page.Items {
		got[bucket.Name.String()] = true
	}
	for _, name := range names {
		if !got[name] {
			t.Errorf("ListBuckets missing %q: %+v", name, page.Items)
		}
	}

	for _, name := range names {
		parsed, err := resource.ParseStoredBucketName(name)
		if err != nil {
			t.Fatal(err)
		}
		bucket, err := set.Storage.GetBucket(ctx, scope, parsed)
		if err != nil {
			t.Fatalf("GetBucket(%q): %v", name, err)
		}
		if bucket.Name.String() != name || bucket.CreationDate != created {
			t.Fatalf("GetBucket(%q) = %+v", name, bucket)
		}
	}
}

// TestStoredReservedBucketObjectIsReadable covers the object conversion that
// runs under ListObjects and GetObject for a bucket read with the stored
// parse.
func TestStoredReservedBucketObjectIsReadable(t *testing.T) {
	const name = "edge-bucket-an"
	obj, err := objectModel(&storagev1.Object{
		Name: "projects/a123456789012/buckets/" + name + "/objects/a.txt",
	})
	if err != nil {
		t.Fatalf("objectModel: %v", err)
	}
	if obj.Bucket.String() != name || obj.Key.String() != "a.txt" {
		t.Fatalf("object = %+v", obj)
	}
}
