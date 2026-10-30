package s3rest

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"
)

// #243: S3 names a missing bucket with its documented sentence, and an
// unsigned ListBuckets is AccessDenied with S3's own text.
func TestNoSuchBucketMessagesMatchAWS(t *testing.T) {
	h, cred, now := harness(t)
	for _, query := range []string{"", "?list-type=2"} {
		res := call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/no-such-bucket"+query, "", nil)
		var body errorXML
		if err := xml.Unmarshal(res.Body.Bytes(), &body); err != nil {
			t.Fatalf("%q: %v", query, err)
		}
		if res.Code != http.StatusNotFound || body.Code != "NoSuchBucket" ||
			body.Message != "The specified bucket does not exist" {
			t.Fatalf("%q: status %d code %q message %q", query, res.Code, body.Code, body.Message)
		}
	}
}

func TestListBucketsWithoutSignatureIsAccessDenied(t *testing.T) {
	h, _, _ := harness(t)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:8082/", nil)
	req.Host = req.URL.Host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body errorXML
	if err := xml.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusForbidden || body.Code != "AccessDenied" || body.Message != "Access Denied" {
		t.Fatalf("status %d code %q message %q", rec.Code, body.Code, body.Message)
	}
}
