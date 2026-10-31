package s3rest

import (
	"net/http"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestStoredReservedBucketNameIsReadable covers #511 on the S3 REST surface:
// ListBuckets, GetBucket and HeadBucket answer 200 for a bucket another path
// stored with a reserved name suffix.
func TestStoredReservedBucketNameIsReadable(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	name, err := resource.ParseStoredBucketName("edge-bucket-an")
	if err != nil {
		t.Fatal(err)
	}
	h, cred, now := harnessWith(t, []resource.Bucket{{
		Name: name, OwnerID: account, CreationDate: "2026-10-09T10:00:00Z",
	}})

	list := call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/", "", nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "<Name>edge-bucket-an</Name>") {
		t.Fatalf("list buckets %d %s", list.Code, list.Body)
	}
	get := call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/edge-bucket-an", "", nil)
	if get.Code != http.StatusOK {
		t.Fatalf("get bucket %d %s", get.Code, get.Body)
	}
	head := call(t, h, cred, now, http.MethodHead, "http://127.0.0.1:8082/edge-bucket-an", "", nil)
	if head.Code != http.StatusOK {
		t.Fatalf("head bucket %d %s", head.Code, head.Body)
	}
}
