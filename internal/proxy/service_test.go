package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

type serviceOrigin struct {
	calls int
	got   *http.Request
	body  string
}

func (f *fixture) serviceOrigin(t *testing.T) *serviceOrigin {
	t.Helper()
	o := &serviceOrigin{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		o.calls, o.got, o.body = o.calls+1, r, string(b)
		w.WriteHeader(http.StatusPartialContent)
	}))
	t.Cleanup(srv.Close)
	if err := f.p.ServiceEndpoint(srv.URL); err != nil {
		t.Fatal(err)
	}
	return o
}

func serviceRequest(method, target, service string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader("payload"))
	for k, v := range map[string]string{
		"X-Vws-Account": "123456789012", "X-Vws-Principal": "principal", "X-Vws-Target-Region": "us-east-1",
		"X-Vws-Target-Service": service, "X-Amz-Security-Token": "caller-token", "Authorization": "caller-signature",
		"X-Amz-Date": "20200101T000000Z", "X-Amz-Content-Sha256": "caller-hash",
		"Range": "bytes=0-3", "X-Amz-Checksum-Mode": "ENABLED", "Cookie": "caller-cookie",
	} {
		r.Header.Set(k, v)
	}
	return r
}

func TestServiceRequestIsReSignedUnchanged(t *testing.T) {
	f := setup(t)
	o := f.serviceOrigin(t)
	w := httptest.NewRecorder()
	f.p.ServeHTTP(w, serviceRequest(http.MethodPut, "/bucket/a%20key?versionId=v1&partNumber=2", "s3"))
	if w.Code != http.StatusPartialContent || o.calls != 1 || f.stsCalls != 1 {
		t.Fatalf("status=%d origin=%d sts=%d body=%s", w.Code, o.calls, f.stsCalls, w.Body)
	}
	r := o.got
	if r.Method != http.MethodPut || r.URL.EscapedPath() != "/bucket/a%20key" ||
		r.URL.RawQuery != "versionId=v1&partNumber=2" || o.body != "payload" ||
		r.Header.Get("Range") != "bytes=0-3" || r.Header.Get("X-Amz-Checksum-Mode") != "ENABLED" ||
		r.Header.Get("Cookie") != "" || r.Header.Get("X-Vws-Account") != "" ||
		r.Header.Get("X-Amz-Security-Token") != "session-token" {
		t.Fatalf("request changed in transit: %s %s %v %q", r.Method, r.URL, r.Header, o.body)
	}
	got := r.Header.Get("Authorization")
	if !strings.Contains(got, "/us-east-1/s3/aws4_request") || !strings.Contains(got, "x-amz-checksum-mode") {
		t.Fatalf("not signed for s3 with its x-amz-* headers: %s", got)
	}
	date, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		t.Fatal(err)
	}
	check := r.Clone(context.Background())
	check.Body = io.NopCloser(strings.NewReader(o.body))
	session := sigv4.Credential{
		AccessKey: "session-canary-key", Secret: "session-canary-secret", SessionToken: "session-token",
	}
	if err := sigv4.SignHeaders(check, session, "s3", "us-east-1", date, "x-amz-checksum-mode"); err != nil {
		t.Fatal(err)
	}
	if check.Header.Get("Authorization") != got {
		t.Fatal("origin received an invalid signature")
	}
}

func TestServiceRefusalsMakeNoOutboundCall(t *testing.T) {
	for name, edit := range map[string]func(*fixture, *http.Request) *http.Request{
		"no service endpoint": func(f *fixture, r *http.Request) *http.Request { f.p.services = ""; return r },
		"presigned query": func(_ *fixture, r *http.Request) *http.Request {
			r.URL.RawQuery = "X-Amz-Signature=abc"
			return r
		},
		"SigV4a region set": func(_ *fixture, r *http.Request) *http.Request {
			r.Header.Set("X-Amz-Region-Set", "*")
			return r
		},
		"malformed service": func(_ *fixture, r *http.Request) *http.Request {
			r.Header.Set("X-Vws-Target-Service", "S3/evil")
			return r
		},
		"method": func(_ *fixture, r *http.Request) *http.Request { r.Method = http.MethodOptions; return r },
		"region": func(_ *fixture, r *http.Request) *http.Request {
			r.Header.Set("X-Vws-Target-Region", "us-east-1.evil")
			return r
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			o := f.serviceOrigin(t)
			w := httptest.NewRecorder()
			f.p.ServeHTTP(w, edit(f, serviceRequest(http.MethodGet, "/bucket/key", "s3")))
			if w.Code != http.StatusForbidden || f.stsCalls != 0 || o.calls != 0 {
				t.Fatalf("status=%d sts=%d origin=%d", w.Code, f.stsCalls, o.calls)
			}
		})
	}
}

func TestServiceEndpointBoundary(t *testing.T) {
	f := setup(t)
	for _, raw := range []string{
		"http://{service}.{region}.amazonaws.com", "https://user@{service}.amazonaws.com",
		"https://{service}.amazonaws.com/path", "https://{service}.amazonaws.com?q=1", "",
	} {
		if err := f.p.ServiceEndpoint(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	if err := f.p.ServiceEndpoint("https://{service}.{region}.amazonaws.com"); err != nil {
		t.Fatal(err)
	}
}
