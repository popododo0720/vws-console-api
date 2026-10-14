package s3rest

import (
	"net/http"
	"testing"
)

func TestChecksumModeReturnsSHA256(t *testing.T) {
	h, cred, now := harness(t)
	if res := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/build-logs", "", nil); res.Code != http.StatusOK {
		t.Fatalf("bucket %d %s", res.Code, res.Body)
	}
	const url = "http://127.0.0.1:8082/build-logs/a.txt"
	if res := call(t, h, cred, now, http.MethodPut, url, "hello", nil); res.Code != http.StatusOK {
		t.Fatalf("put %d %s", res.Code, res.Body)
	}
	enabled := map[string]string{"X-Amz-Checksum-Mode": "ENABLED"}
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		res := call(t, h, cred, now, method, url, "", enabled)
		got := res.Header()
		// base64(sha256("hello"))
		if res.Code != http.StatusOK || got.Get("X-Amz-Checksum-Sha256") != "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=" || got.Get("X-Amz-Checksum-Type") != "FULL_OBJECT" {
			t.Errorf("%s with checksum mode: %d sha256 %q type %q", method, res.Code, got.Get("X-Amz-Checksum-Sha256"), got.Get("X-Amz-Checksum-Type"))
		}
		plain := call(t, h, cred, now, method, url, "", nil)
		if v := plain.Header().Get("X-Amz-Checksum-Sha256"); plain.Code != http.StatusOK || v != "" {
			t.Errorf("%s without checksum mode: %d sha256 %q, want no header", method, plain.Code, v)
		}
	}
}
