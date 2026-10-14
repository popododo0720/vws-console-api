package s3rest

import (
	"net/http"
	"strings"
	"testing"
)

// sha256("hello") and sha256("") in base64.
const (
	helloSHA256 = "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="
	emptySHA256 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
)

func TestPutChecksumSHA256(t *testing.T) {
	h, cred, now := harness(t)
	if res := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/build-logs", "", nil); res.Code != http.StatusOK {
		t.Fatalf("bucket %d %s", res.Code, res.Body)
	}
	for _, tc := range []struct {
		name, key, checksum string
		status              int
		code, message       string
	}{
		{"mismatch", "bad.txt", emptySHA256, http.StatusBadRequest, "BadDigest", "The SHA256 you specified did not match the calculated checksum."},
		{"not base64", "junk.txt", "not-a-checksum", http.StatusBadRequest, "InvalidRequest", "Value for x-amz-checksum-sha256 header is invalid."},
		{"wrong length", "short.txt", "aGVsbG8=", http.StatusBadRequest, "InvalidRequest", "Value for x-amz-checksum-sha256 header is invalid."},
	} {
		url := "http://127.0.0.1:8082/build-logs/" + tc.key
		res := call(t, h, cred, now, http.MethodPut, url, "hello", map[string]string{"X-Amz-Checksum-Sha256": tc.checksum})
		body := res.Body.String()
		if res.Code != tc.status || !strings.Contains(body, "<Code>"+tc.code+"</Code>") || !strings.Contains(body, "<Message>"+tc.message+"</Message>") {
			t.Errorf("%s: %d %s, want %d %s", tc.name, res.Code, body, tc.status, tc.code)
		}
		if got := call(t, h, cred, now, http.MethodGet, url, "", nil); got.Code != http.StatusNotFound {
			t.Errorf("%s: object stored after a rejected put: %d %s", tc.name, got.Code, got.Body)
		}
	}
	ok := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/build-logs/ok.txt", "hello", map[string]string{"X-Amz-Checksum-Sha256": helloSHA256})
	if ok.Code != http.StatusOK {
		t.Fatalf("matching checksum: %d %s", ok.Code, ok.Body)
	}
}
