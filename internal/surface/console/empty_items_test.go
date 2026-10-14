package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// An empty list is "items":[], never null, so clients can iterate it.
func TestEmptyListsAreArrays(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()})
	h := New(rootConfig(svc, account))
	for _, path := range []string{
		"/api/v1/instances", "/api/v1/vpcs", "/api/v1/subnets", "/api/v1/volumes",
		"/api/v1/key-pairs", "/api/v1/addresses", "/api/v1/snapshots", "/api/v1/buckets",
		"/api/v1/instances?state=stopped", "/api/v1/security-groups?groupId=sg-00000000000000000",
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"items":[`) {
			t.Errorf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
}
