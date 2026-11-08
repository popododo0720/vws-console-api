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

// #423 AC2 and AC3: the console takes extraVolumes, the non-root mappings,
// and the launch reads each back on its block device and its volume, deleted
// on termination unless kept. A mapping Normalize refuses is a 400 that
// creates nothing.
func TestConsoleExtraVolumesRoundTrip(t *testing.T) {
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
	vpc := first(do(http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.8.0.0/16"}`, "extra-vpc"), "create vpc")["vpcId"]
	subnet := first(do(http.MethodPost, "/api/v1/subnets", `{"cidrBlock":"10.8.1.0/24","vpcId":"`+vpc.(string)+`"}`,
		"extra-subnet"), "create subnet")["subnetId"]
	launch := func(extras string) string {
		return `{"imageId":"ami-0123456789abcdef0","instanceType":"vws.small","subnetId":"` + subnet.(string) +
			`","extraVolumes":` + extras + `}`
	}
	inst := first(do(http.MethodPost, "/api/v1/instances", launch(
		`[{"deviceName":"/dev/sdf","size":20,"volumeType":"gp3"},`+
			`{"deviceName":"/dev/sdg","size":125,"volumeType":"st1","kept":true}]`), "extra"), "launch")
	devices, ok := inst["blockDeviceMappings"].([]any)
	if !ok || len(devices) != 3 {
		t.Fatalf("launch: %v", inst)
	}
	for i, want := range []struct {
		device, typ string
		size        float64
		dot         bool
	}{{"/dev/sdf", "gp3", 20, true}, {"/dev/sdg", "st1", 125, false}} {
		device := devices[1+i].(map[string]any)
		if device["deviceName"] != want.device || device["deleteOnTermination"] != want.dot {
			t.Fatalf("block device %v, want %+v", device, want)
		}
		var vol map[string]any
		rec := do(http.MethodGet, "/api/v1/volumes/"+device["volumeId"].(string), "", "")
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &vol) != nil {
			t.Fatalf("volume at %s: %d %s", want.device, rec.Code, rec.Body)
		}
		if dot, _ := vol["deleteOnTermination"].(bool); dot != want.dot || vol["volumeType"] != want.typ ||
			vol["size"] != want.size || vol["device"] != want.device {
			t.Fatalf("volume at %s: %v, want %+v", want.device, vol, want)
		}
	}
	refused := do(http.MethodPost, "/api/v1/instances", launch(`[{"deviceName":"xvda","size":8}]`), "extra-root")
	if refused.Code != http.StatusBadRequest || !strings.Contains(refused.Body.String(), "mapped more than once") {
		t.Fatalf("an extra volume at the root device: %d %s", refused.Code, refused.Body)
	}
	var page struct {
		Items []any `json:"items"`
	}
	rec := do(http.MethodGet, "/api/v1/volumes", "", "")
	if json.Unmarshal(rec.Body.Bytes(), &page) != nil || len(page.Items) != 3 {
		t.Fatalf("volumes after a refused launch: %s", rec.Body)
	}
}
