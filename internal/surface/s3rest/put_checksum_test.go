package s3rest

import (
	"net/http"
	"testing"
)

// A PUT that carried a SHA256 checksum gets it back, as S3 does. One without
// a checksum gets neither checksum header.
func TestPutReturnsSHA256WhenRequested(t *testing.T) {
	h, cred, now := harness(t)
	if res := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/sums", "", nil); res.Code != http.StatusOK {
		t.Fatalf("bucket %d %s", res.Code, res.Body)
	}
	for _, tc := range []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{"checksum header", map[string]string{"X-Amz-Checksum-Sha256": helloSHA256}, true},
		{"sdk algorithm", map[string]string{"X-Amz-Sdk-Checksum-Algorithm": "SHA256"}, true},
		{"checksum algorithm", map[string]string{"X-Amz-Checksum-Algorithm": "sha256"}, true},
		{"none", nil, false},
		{"other algorithm", map[string]string{"X-Amz-Sdk-Checksum-Algorithm": "CRC32"}, false},
	} {
		res := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/sums/hello.txt", "hello", tc.headers)
		sum, typ := res.Header().Get("X-Amz-Checksum-Sha256"), res.Header().Get("X-Amz-Checksum-Type")
		if res.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", tc.name, res.Code, res.Body)
		}
		if tc.want && (sum != helloSHA256 || typ != "FULL_OBJECT") {
			t.Errorf("%s: sha256 %q type %q, want %q FULL_OBJECT", tc.name, sum, typ, helloSHA256)
		}
		if !tc.want && (sum != "" || typ != "") {
			t.Errorf("%s: sha256 %q type %q, want neither", tc.name, sum, typ)
		}
	}
}
