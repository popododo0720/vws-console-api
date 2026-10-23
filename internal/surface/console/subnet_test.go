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

func TestConsoleSubnetReportsAvailabilityZone(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()})
	h := New(rootConfig(svc, account))
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
	item := func(rec *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		var acc struct {
			Items []map[string]any `json:"items"`
		}
		if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &acc) != nil || len(acc.Items) != 1 {
			t.Fatalf("create %d %s", rec.Code, rec.Body)
		}
		return acc.Items[0]
	}
	read := func(path string) map[string]any {
		t.Helper()
		rec := do(http.MethodGet, path, "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %d %s", path, rec.Code, rec.Body)
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode %s: %v %s", path, err, rec.Body)
		}
		return got
	}
	vpc := item(do(http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.9.0.0/16"}`, "vpc-subnet-zone"))["vpcId"].(string)
	created := item(do(http.MethodPost, "/api/v1/subnets",
		`{"vpcId":"`+vpc+`","cidrBlock":"10.9.1.0/24","availabilityZone":"vws-1a"}`, "subnet-zone-explicit"))
	id := created["subnetId"].(string)
	if created["availabilityZone"] != "vws-1a" || created["mapPublicIpOnLaunch"] != false {
		t.Fatalf("created %v", created)
	}
	one := read("/api/v1/subnets/" + id)
	if one["availabilityZone"] != "vws-1a" || one["mapPublicIpOnLaunch"] != false {
		t.Fatalf("get %v", one)
	}
	list := read("/api/v1/subnets?pageSize=100")
	items, ok := list["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("list %v", list)
	}
	listed, ok := items[0].(map[string]any)
	if !ok || listed["availabilityZone"] != "vws-1a" || listed["mapPublicIpOnLaunch"] != false {
		t.Fatalf("listed %v", list)
	}
	def := item(do(http.MethodPost, "/api/v1/subnets",
		`{"vpcId":"`+vpc+`","cidrBlock":"10.9.2.0/24"}`, "subnet-zone-default"))
	if def["availabilityZone"] != resource.ZoneName {
		t.Fatalf("default zone %v", def)
	}
	bad := do(http.MethodPost, "/api/v1/subnets",
		`{"vpcId":"`+vpc+`","cidrBlock":"10.9.3.0/24","availabilityZone":"us-east-1a"}`, "subnet-zone-invalid")
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("invalid zone %d %s", bad.Code, bad.Body)
	}
}
