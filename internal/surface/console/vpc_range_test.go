package console

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestCreateVpcRangeMessageMatchesEC2(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	h := New(rootConfig(cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()}), account))
	const want = "The CIDR block range is not valid. The block range must be between a /28 netmask and /16 netmask."
	for i, cidr := range []string{"10.0.0.0/15", "10.2.0.0/29"} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/vpcs",
			strings.NewReader(`{"cidrBlock":"`+cidr+`"}`))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "vpc-range-"+strconv.Itoa(i))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("%s: %d %s, want 400 with %q", cidr, rec.Code, rec.Body, want)
		}
	}
}
