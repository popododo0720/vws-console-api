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

func TestConsoleLaunchesOnADirectSubnet(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	direct, err := resource.Parse[resource.SubnetID]("subnet-direct-prod")
	if err != nil {
		t.Fatal(err)
	}
	world := fake.New(fake.Options{Direct: []fake.DirectNetwork{{ID: direct, Cidr: "192.168.200.0/24"}}})
	h := New(rootConfig(cloud.New(cloud.Config{Backends: world.Set()}), account))
	do := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "direct-launch")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	launched := do(http.MethodPost, "/api/v1/instances",
		`{"imageId":"ami-0123456789abcdef0","instanceType":"vws.small","count":1,`+
			`"networkInterfaces":[{"deviceIndex":0,"subnetId":"subnet-direct-prod"}]}`)
	var acc struct {
		Items []struct {
			ID string `json:"instanceId"`
		} `json:"items"`
	}
	if launched.Code != http.StatusAccepted || json.Unmarshal(launched.Body.Bytes(), &acc) != nil || len(acc.Items) != 1 {
		t.Fatalf("launch %d %s", launched.Code, launched.Body)
	}
	got := do(http.MethodGet, "/api/v1/instances/"+acc.Items[0].ID, "")
	var inst struct {
		SubnetID string `json:"subnetId"`
		VpcID    string `json:"vpcId"`
		NICs     []struct {
			DeviceIndex int    `json:"deviceIndex"`
			SubnetID    string `json:"subnetId"`
			VpcID       string `json:"vpcId"`
			PrivateIP   string `json:"privateIpAddress"`
		} `json:"networkInterfaces"`
	}
	if got.Code != http.StatusOK || json.Unmarshal(got.Body.Bytes(), &inst) != nil {
		t.Fatalf("describe %d %s", got.Code, got.Body)
	}
	if inst.SubnetID != "subnet-direct-prod" || inst.VpcID != "vpc-direct" || len(inst.NICs) != 1 ||
		inst.NICs[0].DeviceIndex != 0 || inst.NICs[0].SubnetID != "subnet-direct-prod" ||
		inst.NICs[0].VpcID != "vpc-direct" || inst.NICs[0].PrivateIP == "" {
		t.Fatalf("instance %s", got.Body)
	}
	both := do(http.MethodPost, "/api/v1/instances",
		`{"imageId":"ami-0123456789abcdef0","instanceType":"vws.small","count":1,"subnetId":"subnet-direct-prod",`+
			`"networkInterfaces":[{"deviceIndex":0,"subnetId":"subnet-direct-prod"}]}`)
	if both.Code != http.StatusBadRequest {
		t.Fatalf("subnetId with networkInterfaces %d %s", both.Code, both.Body)
	}
}
