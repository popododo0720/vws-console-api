package s3rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

func TestSubresourceDoesNotOverwrite(t *testing.T) {
	h, cred, now := harness(t)
	bucket := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/build-logs", "", nil)
	if bucket.Code != http.StatusOK {
		t.Fatalf("bucket %d %s", bucket.Code, bucket.Body)
	}
	put := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/build-logs/a.txt", "hello", nil)
	if put.Code != http.StatusOK {
		t.Fatalf("put %d %s", put.Code, put.Body)
	}
	tag := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/build-logs/a.txt?tagging", "gone", nil)
	if tag.Code != http.StatusNotImplemented {
		t.Fatalf("tagging %d %s", tag.Code, tag.Body)
	}
	copyReq := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/build-logs/a.txt", "gone", map[string]string{
		"X-Amz-Copy-Source": "/build-logs/other",
	})
	if copyReq.Code != http.StatusNotImplemented {
		t.Fatalf("copy %d %s", copyReq.Code, copyReq.Body)
	}
	got := call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/build-logs/a.txt", "", nil)
	if got.Code != http.StatusOK || got.Body.String() != "hello" {
		t.Fatalf("get %d %s", got.Code, got.Body)
	}
}

func TestListBucketsContinues(t *testing.T) {
	h, cred, now := harness(t)
	for _, name := range []string{"logs-aaa", "logs-bbb"} {
		res := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/"+name, "", nil)
		if res.Code != http.StatusOK {
			t.Fatalf("bucket %s %d %s", name, res.Code, res.Body)
		}
	}
	first := call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/?max-buckets=1", "", nil)
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), "<IsTruncated>true</IsTruncated>") {
		t.Fatalf("first %d %s", first.Code, first.Body)
	}
	second := call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/?max-buckets=1&continuation-token=logs-aaa", "", nil)
	if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), "logs-bbb") || strings.Contains(second.Body.String(), "logs-aaa") {
		t.Fatalf("second %d %s", second.Code, second.Body)
	}
}

func harness(t *testing.T) (http.Handler, sigv4.Credential, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{Now: func() time.Time { return now }}).Set()})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	h := New(Config{Service: svc, Verifier: sigv4.NewVerifier(sigv4.Verifier{
		Service: sigv4.ServiceS3,
		Region:  resource.RegionName,
		Now:     func() time.Time { return now },
		Lookup: func(_ context.Context, key string) (sigv4.Credential, bool) {
			return cred, key == cred.AccessKey
		},
	})})
	return h, cred, now
}

func call(t *testing.T, h http.Handler, cred sigv4.Credential, now time.Time, method, rawURL, body string, extra map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, rawURL, strings.NewReader(body))
	req.Host = req.URL.Host
	if body != "" {
		req.Header.Set("Content-Type", "text/plain")
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	if err := sigv4.Sign(req, cred, sigv4.ServiceS3, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
