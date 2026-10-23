package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// #91: vws-console reads vpcId and launchTime from DescribeInstances.
func TestConsoleInstanceReportsVpcIDAndLaunchTime(t *testing.T) {
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
	itemOf := func(rec *httptest.ResponseRecorder, code int, where string) map[string]any {
		t.Helper()
		var page struct {
			Items []map[string]any `json:"items"`
		}
		if rec.Code != code || json.Unmarshal(rec.Body.Bytes(), &page) != nil || len(page.Items) == 0 {
			t.Fatalf("%s: %d %s", where, rec.Code, rec.Body)
		}
		return page.Items[0]
	}
	bodyOf := func(rec *httptest.ResponseRecorder, code int, where string) map[string]any {
		t.Helper()
		var item map[string]any
		if rec.Code != code || json.Unmarshal(rec.Body.Bytes(), &item) != nil {
			t.Fatalf("%s: %d %s", where, rec.Code, rec.Body)
		}
		return item
	}
	create := func(path, body, key, where string) map[string]any {
		t.Helper()
		return itemOf(do(http.MethodPost, path, body, key), http.StatusAccepted, where)
	}
	vpcItem := create("/api/v1/vpcs", `{"cidrBlock":"10.6.0.0/16"}`, "vpc-instance-1", "create vpc")
	vpc, ok := vpcItem["vpcId"].(string)
	if !ok {
		t.Fatalf("create vpc has no vpcId: %v", vpcItem)
	}
	subnetBody := `{"cidrBlock":"10.6.1.0/24","vpcId":"` + vpc + `"}`
	subnetItem := create("/api/v1/subnets", subnetBody, "subnet-instance-1", "create subnet")
	subnet, ok := subnetItem["subnetId"].(string)
	if !ok {
		t.Fatalf("create subnet has no subnetId: %v", subnetItem)
	}
	instanceBody := `{"imageId":"ami-0123456789abcdef0","instanceType":"vws.small",` +
		`"subnetId":"` + subnet + `","count":1}`
	created := create("/api/v1/instances", instanceBody, "instance-fields-1", "create instance")
	instance, ok := created["instanceId"].(string)
	if !ok {
		t.Fatalf("create instance has no instanceId: %v", created)
	}

	check := func(where string, item map[string]any) {
		t.Helper()
		if item["vpcId"] != vpc {
			t.Errorf("%s: vpcId %v, want %s", where, item["vpcId"], vpc)
		}
		raw, ok := item["launchTime"].(string)
		if !ok {
			t.Fatalf("%s: no launchTime: %v", where, item)
		}
		at, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			t.Fatalf("%s: launchTime %q: %v", where, raw, err)
		}
		if at.IsZero() {
			t.Errorf("%s: launchTime is zero", where)
		}
	}
	check("create instance", created)
	check("get instance", bodyOf(do(http.MethodGet, "/api/v1/instances/"+instance, "", ""), http.StatusOK, "get instance"))
	check("list instances", itemOf(do(http.MethodGet, "/api/v1/instances", "", ""), http.StatusOK, "list instances"))
}
