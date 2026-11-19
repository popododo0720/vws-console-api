package s3rest

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

func harness(t *testing.T) (http.Handler, sigv4.Credential, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	h := New(Config{Verifier: sigv4.NewVerifier(sigv4.Verifier{
		Service: sigv4.ServiceS3,
		Regions: backend.DefaultRegions(),
		Now:     func() time.Time { return now },
		Auth:    iam.Authenticator(iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account)),
	})})
	return h, cred, now
}

func call(
	t *testing.T, h http.Handler, cred sigv4.Credential, now time.Time, method, rawURL, body string,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, rawURL, strings.NewReader(body))
	req.Host = req.URL.Host
	if body != "" {
		req.Header.Set("Content-Type", "text/plain")
	}
	if err := sigv4.Sign(req, cred, sigv4.ServiceS3, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// VWS hosts no buckets: every signed request to a region that is not an AWS
// region is 501 NotImplemented in S3's error shape, and a second identical
// request answers the same, since nothing is stored between them.
func TestSignedRequestsAreNotImplemented(t *testing.T) {
	h, cred, now := harness(t)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/", ""},
		{http.MethodPut, "/logs", ""},
		{http.MethodGet, "/logs", ""},
		{http.MethodGet, "/logs?list-type=2", ""},
		{http.MethodHead, "/logs", ""},
		{http.MethodDelete, "/logs", ""},
		{http.MethodPut, "/logs/a.txt", "hi"},
		{http.MethodGet, "/logs/a.txt", ""},
		{http.MethodHead, "/logs/a.txt", ""},
		{http.MethodDelete, "/logs/a.txt", ""},
		{http.MethodPost, "/logs?delete", "<Delete/>"},
		{http.MethodPut, "/" + strings.Repeat("a", 64), ""},
		{http.MethodPut, "/logs/" + strings.Repeat("k", 1025), "x"},
	} {
		for attempt := range 2 {
			res := call(t, h, cred, now, tc.method, "http://127.0.0.1:8082"+tc.path, tc.body)
			if res.Code != http.StatusNotImplemented {
				t.Errorf("%s %s (attempt %d): %d %s", tc.method, tc.path, attempt, res.Code, res.Body)
				continue
			}
			var body errorXML
			if err := xml.Unmarshal(res.Body.Bytes(), &body); err != nil {
				t.Errorf("%s %s: %v", tc.method, tc.path, err)
				continue
			}
			if body.Code != "NotImplemented" || body.Message != notServed {
				t.Errorf("%s %s: code %q message %q", tc.method, tc.path, body.Code, body.Message)
			}
		}
	}
}

// The signature is checked first: an unsigned request, an unknown key and a
// nil verifier are S3's 403, never the 501 a signed caller gets.
func TestSignatureIsCheckedBeforeNotImplemented(t *testing.T) {
	h, cred, now := harness(t)
	unsigned := func(h http.Handler) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:8082/", nil)
		req.Host = req.URL.Host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"unsigned":     unsigned(h),
		"nil verifier": unsigned(New(Config{})),
	} {
		var body errorXML
		if err := xml.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rec.Code != http.StatusForbidden || body.Code != "AccessDenied" || body.Message != "Access Denied" {
			t.Errorf("%s: status %d code %q message %q", name, rec.Code, body.Code, body.Message)
		}
	}
	unknown := sigv4.Credential{AccessKey: "AKIDNOPE", Secret: "x", Account: cred.Account}
	res := call(t, h, unknown, now, http.MethodPut, "http://127.0.0.1:8082/logs/a.txt", "hi")
	if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "<Code>InvalidAccessKeyId</Code>") {
		t.Errorf("unknown key: %d %s", res.Code, res.Body)
	}
}
