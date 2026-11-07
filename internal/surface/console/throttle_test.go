package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/throttle"
)

// #393: console EC2 routes spend the same (account, IAM action) buckets as
// the EC2 Query surface. Past the burst a route is 429 ResourceExhausted
// with Retry-After, the console's throttle answer; S3 routes are not limited
// here.
func TestConsoleSharesTheEC2RequestLimit(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)
	requests := throttle.New(throttle.DefaultLimits(), func() time.Time { return now })
	cfg := rootConfig(cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()}), account)
	cfg.Requests = requests
	h := New(cfg)
	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for i := range 100 {
		if rec := get("/api/v1/vpcs"); rec.Code != http.StatusOK {
			t.Fatalf("list %d in the burst: %d %s", i, rec.Code, rec.Body)
		}
	}
	rec := get("/api/v1/vpcs")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" ||
		!strings.Contains(rec.Body.String(), `"code":"ResourceExhausted","message":"Request limit exceeded."`) {
		t.Errorf("list past the burst: %d %q %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body)
	}
	if _, err := requests.Take(account, "ec2:DescribeVpcs"); err == nil {
		t.Error("EC2 Query DescribeVpcs passed after the console drained the bucket")
	}
	if rec := get("/api/v1/subnets"); rec.Code != http.StatusOK {
		t.Errorf("another action: %d %s", rec.Code, rec.Body)
	}
	for range 200 {
		if rec := get("/api/v1/buckets"); rec.Code != http.StatusOK {
			t.Fatalf("s3 route throttled: %d %s", rec.Code, rec.Body)
		}
	}
}
