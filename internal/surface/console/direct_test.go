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

func TestConsoleRefusesDirectNetworkWrites(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	h := New(rootConfig(cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()}), account))
	for _, c := range []struct{ path, body string }{
		{"/api/v1/subnets", `{"vpcId":"vpc-direct","cidrBlock":"192.168.200.0/25"}`},
		{"/api/v1/subnets/subnet-direct-prod/delete", `{}`},
		{"/api/v1/subnets/subnet-direct-prod/tags", `{"tags":{"owner":"me"}}`},
		{"/api/v1/vpcs/vpc-direct/tags", `{"tags":{"owner":"me"}}`},
		{"/api/v1/vpcs/vpc-direct/delete", `{}`},
		{"/api/v1/security-groups", `{"groupName":"web","vpcId":"vpc-direct"}`},
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, c.path, strings.NewReader(c.body))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "direct-write")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var got struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		err := json.Unmarshal(rec.Body.Bytes(), &got)
		if rec.Code != http.StatusForbidden || err != nil || got.Error.Code != "PermissionDenied" {
			t.Errorf("POST %s: %d %s", c.path, rec.Code, rec.Body)
		}
	}
}
