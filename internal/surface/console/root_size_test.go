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

// #423: the console takes rootVolumeSize, refuses one below the image with
// a 400, gives an omitted one the image's size, and lists the image size.
func TestConsoleRootVolumeSizeFollowsTheImage(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	ami, err := resource.Parse[resource.ImageID]("ami-0a1b2c3d4e5f67890")
	if err != nil {
		t.Fatal(err)
	}
	world := fake.New(fake.Options{Images: []resource.Image{{
		ID: ami, OwnerID: account, Name: "big", State: "available", SizeGiB: 20,
	}}})
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
	first := func(rec *httptest.ResponseRecorder, code int, where string) map[string]any {
		t.Helper()
		var page struct {
			Items []map[string]any `json:"items"`
		}
		if rec.Code != code || json.Unmarshal(rec.Body.Bytes(), &page) != nil || len(page.Items) == 0 {
			t.Fatalf("%s: %d %s", where, rec.Code, rec.Body)
		}
		return page.Items[0]
	}
	vpc := first(do(http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.7.0.0/16"}`, "root-size-vpc"),
		http.StatusAccepted, "create vpc")["vpcId"]
	subnet := first(do(http.MethodPost, "/api/v1/subnets", `{"cidrBlock":"10.7.1.0/24","vpcId":"`+vpc.(string)+`"}`,
		"root-size-subnet"), http.StatusAccepted, "create subnet")["subnetId"]
	launch := func(key, size string) *httptest.ResponseRecorder {
		body := `{"imageId":"` + ami.String() + `","instanceType":"vws.small",` +
			`"subnetId":"` + subnet.(string) + `"` + size + `}`
		return do(http.MethodPost, "/api/v1/instances", body, "root-size-"+key)
	}
	if rec := launch("below", `,"rootVolumeSize":19`); rec.Code != http.StatusBadRequest {
		t.Fatalf("a 19 GiB root on a 20 GiB image: %d %s", rec.Code, rec.Body)
	}
	for _, c := range []struct {
		key, size string
		want      float64
	}{
		{"larger", `,"rootVolumeSize":30`, 30},
		{"omitted", "", 20},
		// #429: 1,000 io1 IOPS need 20 GiB at 50 IOPS per GiB, so the
		// ratio is checked on the image's size, not on 8 GiB.
		{"io1-omitted", `,"rootVolumeType":"io1","rootIops":1000`, 20},
	} {
		inst := first(launch(c.key, c.size), http.StatusAccepted, "launch"+c.size)
		devices, ok := inst["blockDeviceMappings"].([]any)
		if !ok || len(devices) != 1 {
			t.Fatalf("launch%s: %v", c.size, inst)
		}
		vol := devices[0].(map[string]any)["volumeId"].(string)
		var got map[string]any
		rec := do(http.MethodGet, "/api/v1/volumes/"+vol, "", "")
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got["size"] != c.want {
			t.Fatalf("launch%s: root volume %d %s, want size %v", c.size, rec.Code, rec.Body, c.want)
		}
	}
	rec := do(http.MethodGet, "/api/v1/images", "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"size":20`) {
		t.Fatalf("list images: %d %s", rec.Code, rec.Body)
	}
}
