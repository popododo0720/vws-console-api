package console

import (
	"net/http"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestGetStoredReservedBucketName covers #511 on the console surface:
// ListBuckets and GetBucket answer 200 for a bucket another path stored with
// a reserved name suffix.
func TestGetStoredReservedBucketName(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	name, err := resource.ParseStoredBucketName("edge-bucket-an")
	if err != nil {
		t.Fatal(err)
	}
	e := newLoginEnv(t, fake.Options{Buckets: []resource.Bucket{{
		Name: name, OwnerID: account, CreationDate: "2026-10-14T08:00:00Z",
	}}})
	bearer := map[string]string{"Authorization": "Bearer tok", "Origin": ""}

	list := e.do(t, http.MethodGet, "/api/v1/buckets", "", bearer)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"name":"edge-bucket-an"`) {
		t.Fatalf("list buckets %d %s", list.Code, list.Body)
	}
	get := e.do(t, http.MethodGet, "/api/v1/buckets/edge-bucket-an", "", bearer)
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"name":"edge-bucket-an"`) {
		t.Fatalf("get bucket %d %s", get.Code, get.Body)
	}
}
