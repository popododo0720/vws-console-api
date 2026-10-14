package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestVpcAndVolumeDetail(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()})
	h := New(Config{Service: svc, Auth: BearerTokens{"tok": {Account: account, Subject: "t"}}})
	do := func(method, path, body, key string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", key)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	created := func(rec *httptest.ResponseRecorder, field string) string {
		t.Helper()
		var acc struct {
			Items []map[string]any `json:"items"`
		}
		if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &acc) != nil || len(acc.Items) != 1 {
			t.Fatalf("create %d %s", rec.Code, rec.Body)
		}
		return acc.Items[0][field].(string)
	}
	vpc := created(do(http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.4.0.0/16"}`, "vpc-detail-1"), "vpcId")
	vol := created(do(http.MethodPost, "/api/v1/volumes", `{"size":2,"availabilityZone":"vws-1a"}`, "vol-detail-1"), "volumeId")
	for path, want := range map[string]string{
		"/api/v1/vpcs/" + vpc:    `"vpcId":"` + vpc + `"`,
		"/api/v1/volumes/" + vol: `"volumeId":"` + vol + `"`,
	} {
		rec := do(http.MethodGet, path, "", "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) || strings.Contains(rec.Body.String(), `"items"`) {
			t.Errorf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
	for _, path := range []string{"/api/v1/vpcs/vpc-00000000000000000", "/api/v1/volumes/vol-00000000000000000"} {
		if rec := do(http.MethodGet, path, "", ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
	if rec := do(http.MethodGet, "/api/v1/vpcs/not-an-id", "", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed id: %d %s", rec.Code, rec.Body)
	}
}
