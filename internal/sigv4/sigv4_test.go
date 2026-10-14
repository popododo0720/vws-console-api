package sigv4

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	cred := cred(t)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "http://127.0.0.1:8082/build-logs/a.txt", strings.NewReader("hello"))
	req.Host = "127.0.0.1:8082"
	req.Header.Set("Content-Type", "text/plain")
	if err := Sign(req, cred, ServiceS3, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	v := verifier(cred, ServiceS3, now)
	caller, err := v.Verify(req)
	if err != nil {
		t.Fatal(err)
	}
	if caller.Account != cred.Account || caller.Subject != cred.AccessKey {
		t.Fatalf("caller %+v", caller)
	}
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("body %q", got)
	}
}

func TestTamperAndSkew(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	cred := cred(t)
	v := verifier(cred, ServiceEC2, now)

	tampered := signed(t, cred, ServiceEC2, now, http.MethodGet, "http://127.0.0.1:8081/?Action=DescribeInstances&Version=2016-11-15", "")
	q := tampered.URL.Query()
	q.Set("Action", "StopInstances")
	tampered.URL.RawQuery = q.Encode()
	if _, err := v.Verify(tampered); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Fatalf("tamper: %v", err)
	}

	late := signed(t, cred, ServiceEC2, now, http.MethodGet, "http://127.0.0.1:8081/", "")
	late.Header.Set("X-Amz-Date", now.Add(time.Hour).Format("20060102T150405Z"))
	if _, err := v.Verify(late); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Fatalf("skew: %v", err)
	}
}

func TestPresignRefused(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:8081/?X-Amz-Algorithm=AWS4-HMAC-SHA256", nil)
	v := verifier(cred(t), ServiceEC2, time.Now())
	if _, err := v.Verify(req); resource.CodeOf(err) != resource.CodeUnimplemented {
		t.Fatalf("got %v", err)
	}
}

func TestQueryWithoutPayloadHeader(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	c := cred(t)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8081/", strings.NewReader("Action=DescribeInstances&Version=2016-11-15"))
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := sign(req, c, ServiceEC2, resource.RegionName, now, false); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("X-Amz-Content-Sha256") != "" {
		t.Fatal("payload header was set")
	}
	if _, err := verifier(c, ServiceEC2, now).Verify(req); err != nil {
		t.Fatal(err)
	}
}

func TestUnsignedPayloadAndUnreadBody(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	c := cred(t)
	v := verifier(c, ServiceEC2, now)
	req := signed(t, c, ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", "Action=DescribeInstances&Version=2016-11-15")
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	if _, err := v.Verify(req); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Fatalf("unsigned: %v", err)
	}

	unread := signed(t, c, ServiceEC2, now, http.MethodGet, "http://127.0.0.1:8081/", "")
	unread.Body = io.NopCloser(errReader{})
	auth := unread.Header.Get("Authorization")
	unread.Header.Set("Authorization", strings.Replace(auth, c.AccessKey, "UNKNOWNKEY", 1))
	if _, err := v.Verify(unread); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Fatalf("unknown key: %v", err)
	}
}

func TestTooManyQueryParams(t *testing.T) {
	var parts []string
	for i := 0; i <= maxQueryParams; i++ {
		parts = append(parts, fmt.Sprintf("p%d=1", i))
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:8081/?"+strings.Join(parts, "&"), nil)
	req.Host = req.URL.Host
	if _, err := verifier(cred(t), ServiceEC2, time.Now()).Verify(req); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("got %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("body was read") }

func TestPinnedSignature(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	c := cred(t)
	req := signed(t, c, ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", "Action=RunInstances&Version=2016-11-15")
	const want = "e04414d15be935a21a8cf1579a33dc4293efbb412419e869bf04b7181ddd4528"
	if got := signatureOf(req); got != want {
		t.Fatalf("signature %s", got)
	}
}

func cred(t *testing.T) Credential {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return Credential{AccessKey: "AKIDEXAMPLE", Secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", Account: account}
}

func verifier(c Credential, service Service, now time.Time) *Verifier {
	return NewVerifier(Verifier{
		Service: service,
		Region:  resource.RegionName,
		Now:     func() time.Time { return now },
		Keys: Lookup(func(_ context.Context, key string) (Credential, bool) {
			return c, key == c.AccessKey
		}),
	})
}

func signed(t *testing.T, c Credential, service Service, now time.Time, method, rawURL, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, rawURL, strings.NewReader(body))
	req.Host = req.URL.Host
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if err := Sign(req, c, service, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	return req
}

func signatureOf(r *http.Request) string {
	const mark = "Signature="
	h := r.Header.Get("Authorization")
	i := strings.Index(h, mark)
	if i < 0 {
		return ""
	}
	return h[i+len(mark):]
}
