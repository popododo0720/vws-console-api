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

// #423 AC3: the console takes rootVolumeKept, the root mapping's
// Ebs.DeleteOnTermination=false, and the launch reads it back on the block
// device and on the root volume. Omitted, the root is deleted on
// termination, as on EC2.
func TestConsoleRootVolumeKeptRoundTrips(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	world := fake.New(fake.Options{})
	h := New(rootConfig(cloud.New(cloud.Config{Backends: world.Set()}), account))
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
	first := func(rec *httptest.ResponseRecorder, where string) map[string]any {
		t.Helper()
		var page struct {
			Items []map[string]any `json:"items"`
		}
		if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &page) != nil || len(page.Items) == 0 {
			t.Fatalf("%s: %d %s", where, rec.Code, rec.Body)
		}
		return page.Items[0]
	}
	vpc := first(do(http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.8.0.0/16"}`, "kept-vpc"), "create vpc")["vpcId"]
	subnet := first(do(http.MethodPost, "/api/v1/subnets", `{"cidrBlock":"10.8.1.0/24","vpcId":"`+vpc.(string)+`"}`,
		"kept-subnet"), "create subnet")["subnetId"]
	for _, c := range []struct {
		key, field string
		want       bool
	}{
		{"kept", `,"rootVolumeKept":true`, false},
		{"omitted", "", true},
	} {
		body := `{"imageId":"ami-0123456789abcdef0","instanceType":"vws.small","subnetId":"` + subnet.(string) + `"` +
			c.field + `}`
		inst := first(do(http.MethodPost, "/api/v1/instances", body, "kept-"+c.key), "launch "+c.key)
		devices, ok := inst["blockDeviceMappings"].([]any)
		if !ok || len(devices) != 1 {
			t.Fatalf("launch %s: %v", c.key, inst)
		}
		device := devices[0].(map[string]any)
		if device["deleteOnTermination"] != c.want {
			t.Fatalf("launch %s: block device %v, want deleteOnTermination %v", c.key, device, c.want)
		}
		var vol map[string]any
		rec := do(http.MethodGet, "/api/v1/volumes/"+device["volumeId"].(string), "", "")
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &vol) != nil {
			t.Fatalf("launch %s: root volume %d %s", c.key, rec.Code, rec.Body)
		}
		if got, _ := vol["deleteOnTermination"].(bool); got != c.want {
			t.Fatalf("launch %s: root volume %v, want deleteOnTermination %v", c.key, vol, c.want)
		}
	}
}
