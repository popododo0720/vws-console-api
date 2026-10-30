package s3rest

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// takenMessage is the text S3 sends with BucketAlreadyExists.
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/ErrorResponses.html
const takenMessage = "The requested bucket name is not available. " +
	"The bucket namespace is shared by all users of the system. " +
	"Please select a different name and try again."

// TestCreateBucketTwiceIsBucketAlreadyOwnedByYou covers #315. VWS's region
// (resource.RegionName, vws-1) is not us-east-1, so a create for a bucket
// the caller owns is 409 BucketAlreadyOwnedByYou, not the legacy 200.
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html
func TestCreateBucketTwiceIsBucketAlreadyOwnedByYou(t *testing.T) {
	h, cred, now := harness(t)
	if res := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/owned-logs", "", nil); res.Code != 200 {
		t.Fatalf("first create %d %s", res.Code, res.Body)
	}
	again := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/owned-logs", "", nil)
	if again.Code != http.StatusConflict {
		t.Fatalf("second create %d %s, want 409", again.Code, again.Body)
	}
	assertBucketErr(t, again, "BucketAlreadyOwnedByYou", resource.BucketOwnedMessage, "owned-logs")
	if loc := again.Header().Get("Location"); loc != "" {
		t.Errorf("refused create set Location %q", loc)
	}
	list := call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/", "", nil)
	if list.Code != http.StatusOK || strings.Count(list.Body.String(), "<Name>owned-logs</Name>") != 1 {
		t.Fatalf("list %d %s", list.Code, list.Body)
	}
}

// TestTakenBucketNameIsBucketAlreadyExists pins the answer for a name
// another account holds: 409 BucketAlreadyExists with S3's text.
func TestTakenBucketNameIsBucketAlreadyExists(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/taken-logs", nil)
	writeErr(rec, req, resource.AlreadyExists(resource.KindBucket, "taken-logs"), "taken-logs")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	assertBucketErr(t, rec, "BucketAlreadyExists", takenMessage, "taken-logs")
}

func assertBucketErr(t *testing.T, rec *httptest.ResponseRecorder, code, message, bucket string) {
	t.Helper()
	var body errorXML
	if err := xml.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != code || body.Message != message {
		t.Errorf("error %q %q, want %q %q", body.Code, body.Message, code, message)
	}
	if !strings.Contains(rec.Body.String(), "<BucketName>"+bucket+"</BucketName>") {
		t.Errorf("body has no BucketName %s: %s", bucket, rec.Body)
	}
}

// TestOwnedCreateRegionRule pins the documented split: 200 for an owned
// bucket only in us-east-1, 409 BucketAlreadyOwnedByYou elsewhere, and
// VWS's own region is elsewhere.
func TestOwnedCreateRegionRule(t *testing.T) {
	for region, want := range map[string]bool{
		"us-east-1":         true,
		"us-west-2":         false,
		"eu-west-1":         false,
		resource.RegionName: false,
	} {
		if got := ownedCreateSucceeds(region); got != want {
			t.Errorf("%s: %v, want %v", region, got, want)
		}
	}
	if got := s3Code(resource.BucketAlreadyOwned("b")); got != "BucketAlreadyOwnedByYou" {
		t.Errorf("owned code %s", got)
	}
}

// TestBucketDeletingIsOperationAborted pins #321: a create while the caller's
// own bucket is still being deleted is 409 OperationAborted with S3's text,
// not BucketAlreadyExists (another account) or BucketAlreadyOwnedByYou.
func TestBucketDeletingIsOperationAborted(t *testing.T) {
	e := resource.AsError(resource.BucketDeleting("b"))
	if got := s3Code(e); got != "OperationAborted" {
		t.Errorf("code %s, want OperationAborted", got)
	}
	if got := statusOf(e); got != 409 {
		t.Errorf("status %d, want 409", got)
	}
	if e.Message != resource.BucketDeletingMessage {
		t.Errorf("message %q", e.Message)
	}
	if got := s3Code(resource.AsError(resource.Conflict(resource.KindBucket, "b", "not empty"))); got != "BucketNotEmpty" {
		t.Errorf("plain conflict code %s, want BucketNotEmpty", got)
	}
}
