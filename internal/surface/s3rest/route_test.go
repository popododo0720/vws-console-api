package s3rest

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestListObjectsV2(t *testing.T) {
	h, cred, now := harness(t)
	bucket := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/build-logs", "", nil)
	if bucket.Code != http.StatusOK {
		t.Fatalf("bucket %d %s", bucket.Code, bucket.Body)
	}
	for _, key := range []string{"a.txt", "b/c.txt", "b/d.txt", "c.txt"} {
		res := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/build-logs/"+key, "x", nil)
		if res.Code != http.StatusOK {
			t.Fatalf("put %s %d %s", key, res.Code, res.Body)
		}
	}
	listed := call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/build-logs?list-type=2&delimiter=/", "", nil)
	page := mustList(t, listed)
	body := listed.Body.String()
	if listed.Code != http.StatusOK || !strings.Contains(body, "<Key>a.txt</Key>") || !strings.Contains(body, "<Key>c.txt</Key>") {
		t.Fatalf("list %d %s", listed.Code, body)
	}
	if strings.Contains(body, "b/c.txt") || !hasPrefix(page, "b/") || strings.Contains(body, "<Owner>") {
		t.Fatalf("delimiter %s", body)
	}
	owned := call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/build-logs?list-type=2&delimiter=/&fetch-owner=true", "", nil)
	if owned.Code != http.StatusOK || !strings.Contains(owned.Body.String(), "<ID>123456789012</ID>") {
		t.Fatalf("owner %d %s", owned.Code, owned.Body)
	}
	firstRec := call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/build-logs?list-type=2&delimiter=/&max-keys=1", "", nil)
	first := mustList(t, firstRec)
	token, err := base64.RawURLEncoding.DecodeString(first.NextContinuationToken)
	if firstRec.Code != http.StatusOK || !first.IsTruncated || string(token) != "a.txt" || err != nil {
		t.Fatalf("page %v %d %s", err, firstRec.Code, firstRec.Body)
	}
	deleted := call(t, h, cred, now, http.MethodDelete, "http://127.0.0.1:8082/build-logs/a.txt", "", nil)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete %d %s", deleted.Code, deleted.Body)
	}
	nextURL := "http://127.0.0.1:8082/build-logs?list-type=2&delimiter=/&max-keys=1&continuation-token=" + url.QueryEscape(first.NextContinuationToken)
	second := mustList(t, call(t, h, cred, now, http.MethodGet, nextURL, "", nil))
	if !hasPrefix(second, "b/") || strings.Contains(keysOf(second), "a.txt") {
		t.Fatalf("next %+v", second)
	}
	encoded := call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/build-logs?list-type=2&delimiter=/&encoding-type=url&prefix=b/", "", nil)
	if encoded.Code != http.StatusOK || !strings.Contains(encoded.Body.String(), "<Key>b%2Fc.txt</Key>") || !strings.Contains(encoded.Body.String(), "<Prefix>b%2F</Prefix>") {
		t.Fatalf("encoded %d %s", encoded.Code, encoded.Body)
	}
	inside := mustList(t, call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/build-logs?list-type=2&delimiter=/&start-after=b/c.txt", "", nil))
	if !hasPrefix(inside, "b/") || !strings.Contains(keysOf(inside), "c.txt") {
		t.Fatalf("start-after %+v", inside)
	}
	for _, rawURL := range []string{
		"http://127.0.0.1:8082/build-logs?list-type=2&max-keys=0",
		"http://127.0.0.1:8082/build-logs?list-type=2&continuation-token=!!!!",
		"http://127.0.0.1:8082/build-logs?list-type=3",
		"http://127.0.0.1:8082/build-logs?list-type=2&marker=a",
		"http://127.0.0.1:8082/build-logs?continuation-token=YQ",
		"http://127.0.0.1:8082/build-logs?max-keys=0",
	} {
		bad := call(t, h, cred, now, http.MethodGet, rawURL, "", nil)
		if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "InvalidArgument") {
			t.Fatalf("invalid %s %d %s", rawURL, bad.Code, bad.Body)
		}
	}
	for _, rawURL := range []string{
		"http://127.0.0.1:8082/build-logs?encryption",
	} {
		stub := call(t, h, cred, now, http.MethodGet, rawURL, "", nil)
		if stub.Code != http.StatusNotImplemented || !strings.Contains(stub.Body.String(), "NotImplemented") {
			t.Fatalf("stub %s %d %s", rawURL, stub.Code, stub.Body)
		}
	}
	capped := mustList(t, call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/build-logs?list-type=2&max-keys=5000", "", nil))
	if capped.MaxKeys != 1000 {
		t.Fatalf("max-keys %+v", capped)
	}
	head := call(t, h, cred, now, http.MethodHead, "http://127.0.0.1:8082/build-logs", "", nil)
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("head bucket %d %s", head.Code, head.Body)
	}
	missingHead := call(t, h, cred, now, http.MethodHead, "http://127.0.0.1:8082/missing-logs", "", nil)
	if missingHead.Code != http.StatusNotFound || !strings.Contains(missingHead.Body.String(), "NoSuchBucket") {
		t.Fatalf("head missing %d %s", missingHead.Code, missingHead.Body)
	}
	missing := call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/missing-logs?list-type=2", "", nil)
	if missing.Code != http.StatusNotFound || !strings.Contains(missing.Body.String(), "NoSuchBucket") {
		t.Fatalf("missing %d %s", missing.Code, missing.Body)
	}
}

func TestListObjectsV1(t *testing.T) {
	h, cred, now := harness(t)
	if res := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/build-logs", "", nil); res.Code != http.StatusOK {
		t.Fatalf("bucket %d %s", res.Code, res.Body)
	}
	for _, key := range []string{"a.txt", "b/c.txt", "b/d.txt", "c.txt"} {
		if res := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/build-logs/"+key, "x", nil); res.Code != http.StatusOK {
			t.Fatalf("put %s %d %s", key, res.Code, res.Body)
		}
	}
	all := mustListV1(t, call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/build-logs", "", nil))
	if keysOfV1(all) != "a.txt,b/c.txt,b/d.txt,c.txt" || all.IsTruncated || all.MaxKeys != 1000 || all.Contents[0].Owner == nil {
		t.Fatalf("all %+v", all)
	}
	prefixed := mustListV1(t, call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/build-logs?prefix=b/", "", nil))
	if keysOfV1(prefixed) != "b/c.txt,b/d.txt" || prefixed.Prefix != "b/" {
		t.Fatalf("prefix %+v", prefixed)
	}
	rolled := mustListV1(t, call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/build-logs?list-type=1&delimiter=/", "", nil))
	if keysOfV1(rolled) != "a.txt,c.txt" || len(rolled.CommonPrefixes) != 1 || rolled.CommonPrefixes[0].Prefix != "b/" {
		t.Fatalf("delimiter %+v", rolled)
	}
	var seen []string
	marker := ""
	for range 5 {
		page := mustListV1(t, call(t, h, cred, now, http.MethodGet,
			"http://127.0.0.1:8082/build-logs?delimiter=/&max-keys=1&marker="+url.QueryEscape(marker), "", nil))
		if page.Marker != marker || len(page.Contents)+len(page.CommonPrefixes) != 1 {
			t.Fatalf("page after %q %+v", marker, page)
		}
		for _, item := range page.Contents {
			seen = append(seen, item.Key)
		}
		for _, item := range page.CommonPrefixes {
			seen = append(seen, item.Prefix)
		}
		if !page.IsTruncated {
			if page.NextMarker != "" {
				t.Fatalf("last page has NextMarker %+v", page)
			}
			break
		}
		marker = page.NextMarker
	}
	if strings.Join(seen, ",") != "a.txt,b/,c.txt" {
		t.Fatalf("paged %v", seen)
	}
	encoded := call(t, h, cred, now, http.MethodGet, "http://127.0.0.1:8082/build-logs?encoding-type=url&prefix=b/", "", nil)
	if encoded.Code != http.StatusOK || !strings.Contains(encoded.Body.String(), "<Key>b%2Fc.txt</Key>") {
		t.Fatalf("encoded %d %s", encoded.Code, encoded.Body)
	}
}

func mustListV1(t *testing.T, rec *httptest.ResponseRecorder) listObjectsV1XML {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("list %d %s", rec.Code, rec.Body)
	}
	var page listObjectsV1XML
	if err := xml.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("xml %v %s", err, rec.Body)
	}
	return page
}

func keysOfV1(page listObjectsV1XML) string {
	var keys []string
	for _, item := range page.Contents {
		keys = append(keys, item.Key)
	}
	return strings.Join(keys, ",")
}

func mustList(t *testing.T, rec *httptest.ResponseRecorder) listObjectsXML {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("list %d %s", rec.Code, rec.Body)
	}
	var page listObjectsXML
	if err := xml.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("xml %v %s", err, rec.Body)
	}
	return page
}

func hasPrefix(page listObjectsXML, prefix string) bool {
	for _, item := range page.CommonPrefixes {
		if item.Prefix == prefix {
			return true
		}
	}
	return false
}

func keysOf(page listObjectsXML) string {
	var keys []string
	for _, item := range page.Contents {
		keys = append(keys, item.Key)
	}
	return strings.Join(keys, ",")
}

func TestHeadObject(t *testing.T) {
	h, cred, now := harness(t)
	if res := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/build-logs", "", nil); res.Code != http.StatusOK {
		t.Fatalf("bucket %d %s", res.Code, res.Body)
	}
	if res := call(t, h, cred, now, http.MethodPut, "http://127.0.0.1:8082/build-logs/a.txt", "hello", nil); res.Code != http.StatusOK {
		t.Fatalf("put %d %s", res.Code, res.Body)
	}
	head := call(t, h, cred, now, http.MethodHead, "http://127.0.0.1:8082/build-logs/a.txt", "", nil)
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") != "5" || head.Header().Get("ETag") == "" {
		t.Fatalf("head %d %s len %s", head.Code, head.Body, head.Header().Get("Content-Length"))
	}
	missing := call(t, h, cred, now, http.MethodHead, "http://127.0.0.1:8082/build-logs/missing.txt", "", nil)
	if missing.Code != http.StatusNotFound || !strings.Contains(missing.Body.String(), "NoSuchKey") {
		t.Fatalf("missing %d %s", missing.Code, missing.Body)
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
	req := httptest.NewRequestWithContext(t.Context(), method, rawURL, strings.NewReader(body))
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
