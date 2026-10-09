package interop

import (
	"bytes"
	"context"
	"encoding"
	"encoding/json"
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
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
	"github.com/popododo0720/vws-console-api/internal/surface/s3rest"
)

func TestConsoleAndQueryLaunchTheSameInstance(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account := mustParse[resource.AccountID](t, "123456789012")
	caller := resource.Caller{Account: account, Subject: "console"}
	world := fake.New(fake.Options{
		Now:     func() time.Time { return now },
		Entropy: bytes.NewReader(bytes.Repeat([]byte{0x33}, 1<<12)),
	})
	svc := cloud.New(cloud.Config{Backends: world.Set()})
	ui := console.New(console.Config{Service: svc, Auth: console.BearerTokens{"tok-console": caller}})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	query := ec2query.New(ec2query.Config{Service: svc, Verifier: verifier(cred, sigv4.ServiceEC2, now)})

	body := `{"imageId":"ami-0123456789abcdef0","instanceType":"vws.small","subnetId":"subnet-0123456789abcdef0","count":1}`
	consoleRes := call(t, ui, http.MethodPost, "/api/v1/instances", body, map[string]string{
		"Authorization":   "Bearer tok-console",
		"Content-Type":    "application/json",
		"Idempotency-Key": "launch-web-1",
	})
	if consoleRes.Code != http.StatusAccepted {
		t.Fatalf("console %d %s", consoleRes.Code, consoleRes.Body)
	}
	var accepted struct {
		Items []struct {
			InstanceID string `json:"instanceId"`
			State      string `json:"state"`
		} `json:"items"`
		Operation struct {
			ID string `json:"id"`
		} `json:"operation"`
	}
	if err := json.Unmarshal(consoleRes.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Items[0].State != "pending" || !strings.HasPrefix(accepted.Operation.ID, "op-compute-") {
		t.Fatalf("%s", consoleRes.Body)
	}

	form := url.Values{}
	form.Set("Action", "RunInstances")
	form.Set("Version", ec2query.Version)
	form.Set("ImageId", "ami-0123456789abcdef0")
	form.Set("InstanceType", "vws.small")
	form.Set("SubnetId", "subnet-0123456789abcdef0")
	form.Set("MinCount", "1")
	form.Set("MaxCount", "1")
	form.Set("ClientToken", "launch-web-1")
	queryRes := serveSigned(t, query, cred, sigv4.ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", form.Encode())
	if queryRes.Code != http.StatusOK || !strings.Contains(queryRes.Body.String(), accepted.Items[0].InstanceID) {
		t.Fatalf("query %d %s", queryRes.Code, queryRes.Body)
	}

	got := call(t, ui, http.MethodGet, "/api/v1/instances/"+accepted.Items[0].InstanceID, "", map[string]string{
		"Authorization": "Bearer tok-console",
	})
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"state":"running"`) {
		t.Fatalf("describe %d %s", got.Code, got.Body)
	}

	describe := url.Values{}
	describe.Set("Action", "DescribeInstances")
	describe.Set("Version", ec2query.Version)
	describe.Set("InstanceId.1", accepted.Items[0].InstanceID)
	dRes := serveSigned(t, query, cred, sigv4.ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", describe.Encode())
	if dRes.Code != http.StatusOK || !strings.Contains(dRes.Body.String(), "<name>running</name>") {
		t.Fatalf("ec2 describe %d %s", dRes.Code, dRes.Body)
	}
}

func TestS3ObjectRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account := mustParse[resource.AccountID](t, "123456789012")
	world := fake.New(fake.Options{Now: func() time.Time { return now }})
	svc := cloud.New(cloud.Config{Backends: world.Set()})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	s3 := s3rest.New(s3rest.Config{Service: svc, Verifier: verifier(cred, sigv4.ServiceS3, now)})

	bucketRes := serveSigned(t, s3, cred, sigv4.ServiceS3, now, http.MethodPut, "http://127.0.0.1:8082/build-logs", "")
	if bucketRes.Code != http.StatusOK {
		t.Fatalf("bucket %d %s", bucketRes.Code, bucketRes.Body)
	}
	putRes := serveSigned(t, s3, cred, sigv4.ServiceS3, now, http.MethodPut, "http://127.0.0.1:8082/build-logs/a.txt", "hello")
	if putRes.Code != http.StatusOK {
		t.Fatalf("put %d %s", putRes.Code, putRes.Body)
	}
	getRes := serveSigned(t, s3, cred, sigv4.ServiceS3, now, http.MethodGet, "http://127.0.0.1:8082/build-logs/a.txt", "")
	if getRes.Code != http.StatusOK || getRes.Body.String() != "hello" {
		t.Fatalf("get %d %s", getRes.Code, getRes.Body)
	}

	ui := console.New(console.Config{
		Service: svc,
		Auth:    console.BearerTokens{"tok-console": {Account: account, Subject: "console"}},
	})
	listed := call(t, ui, http.MethodGet, "/api/v1/buckets", "", map[string]string{"Authorization": "Bearer tok-console"})
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), "build-logs") {
		t.Fatalf("console list %d %s", listed.Code, listed.Body)
	}
}

func verifier(cred sigv4.Credential, service sigv4.Service, now time.Time) *sigv4.Verifier {
	return sigv4.NewVerifier(sigv4.Verifier{
		Service: service,
		Region:  resource.RegionName,
		Now:     func() time.Time { return now },
		Lookup: func(_ context.Context, key string) (sigv4.Credential, bool) {
			return cred, key == cred.AccessKey
		},
	})
}

func serveSigned(t *testing.T, h http.Handler, cred sigv4.Credential, service sigv4.Service, now time.Time, method, rawURL, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, rawURL, strings.NewReader(body))
	req.Host = req.URL.Host
	if body != "" {
		if service == sigv4.ServiceS3 {
			req.Header.Set("Content-Type", "text/plain")
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err := sigv4.Sign(req, cred, service, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func call(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func mustParse[T any, PT interface {
	*T
	encoding.TextUnmarshaler
}](t *testing.T, s string) T {
	t.Helper()
	v, err := resource.Parse[T, PT](s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
