package regionapi

import (
	"reflect"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestStoredBucketNamesRoundTrip(t *testing.T) {
	for _, raw := range []string{"ab", "xn--bucket", "edge-bucket-an"} {
		t.Run(raw, func(t *testing.T) {
			scope := testScope(t)
			name, err := resource.ParseStoredBucketName(raw)
			if err != nil {
				t.Fatal(err)
			}
			want := resource.Bucket{Name: name, OwnerID: scope.Account}
			set := fake.New(fake.Options{Buckets: []resource.Bucket{want}}).Set()
			key, err := resource.Parse[resource.ObjectKey]("stored")
			if err != nil {
				t.Fatal(err)
			}
			obj, err := set.Storage.PutObject(t.Context(), scope, resource.PutObjectRequest{
				Bucket: name, Key: key, Size: 4,
			}, strings.NewReader("data"))
			if err != nil {
				t.Fatal(err)
			}
			c, _ := loopback(t, config(set))
			var bucket resource.Bucket
			if err := c.Call(t.Context(), "Storage", "GetBucket", scope, name, &bucket); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(bucket, want) {
				t.Fatalf("bucket changed: %+v", bucket)
			}
			var list resource.Page[resource.Bucket]
			if err := c.Call(t.Context(), "Storage", "ListBuckets", scope,
				resource.BucketQuery{Page: resource.PageRequest{Size: 50}}, &list); err != nil {
				t.Fatal(err)
			}
			if len(list.Items) != 1 || list.Items[0] != want {
				t.Fatalf("list changed: %+v", list)
			}
			var object ObjectResult
			if err := c.Call(t.Context(), "Storage", "GetObject", scope,
				resource.GetObjectRequest{Bucket: name, Key: key}, &object); err != nil {
				t.Fatal(err)
			}
			if object.Object != obj || string(object.Body) != "data" {
				t.Fatalf("object changed: %+v", object)
			}
			var objects resource.ObjectListing
			if err := c.Call(t.Context(), "Storage", "ListObjects", scope,
				resource.ObjectQuery{Bucket: name, MaxKeys: 1000}, &objects); err != nil {
				t.Fatal(err)
			}
			if len(objects.Objects) != 1 || objects.Objects[0] != obj {
				t.Fatalf("objects changed: %+v", objects)
			}
		})
	}
}
