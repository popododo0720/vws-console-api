package s3rest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// TestMalformedNamesAndBodies sends bucket names, keys, and bodies past
// the model limits. Each is a 4xx and leaves nothing behind.
func TestMalformedNamesAndBodies(t *testing.T) {
	h, cred, now := harness(t)
	if res := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/edge-bucket", "", nil); res.Code != http.StatusOK {
		t.Fatalf("bucket %d %s", res.Code, res.Body)
	}
	for _, tc := range []struct {
		name, method, url, body string
		status                  int
		code                    string
	}{
		{"uppercase bucket", http.MethodPut, "/Edge-Bucket", "", 400, "InvalidArgument"},
		{"short bucket", http.MethodPut, "/ab", "", 400, "InvalidArgument"},
		{"long bucket", http.MethodPut, "/" + strings.Repeat("a", 64), "", 400, "InvalidArgument"},
		{"ip bucket", http.MethodPut, "/192.168.0.1", "", 400, "InvalidArgument"},
		{"long key", http.MethodPut, "/edge-bucket/" + strings.Repeat("k", 1025), "x", 400, "InvalidArgument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := call(t, h, cred, now, tc.method, "http://127.0.0.1:8082"+tc.url, tc.body, nil)
			if res.Code != tc.status || !strings.Contains(res.Body.String(), "<Code>"+tc.code+"</Code>") {
				t.Fatalf("%d %s", res.Code, res.Body)
			}
		})
	}

	// Sign a small body, then send one byte past the cap. The cap is checked
	// before the signature, so the answer is the size and not AccessDenied.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "http://127.0.0.1:8082/edge-bucket/big", strings.NewReader("x"))
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "text/plain")
	if err := sigv4.Sign(req, cred, sigv4.ServiceS3, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	req.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", resource.MaxObjectBytes+1)))
	big := httptest.NewRecorder()
	h.ServeHTTP(big, req)
	if big.Code != http.StatusRequestEntityTooLarge || !strings.Contains(big.Body.String(), "<Code>EntityTooLarge</Code>") {
		t.Fatalf("large body %d %s", big.Code, big.Body)
	}
	if res := call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/edge-bucket/big", "", nil); res.Code != http.StatusNotFound {
		t.Fatalf("rejected body was stored: %d %s", res.Code, res.Body)
	}
}
