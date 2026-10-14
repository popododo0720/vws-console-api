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

func TestBatchInstanceActions(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()})
	h := New(Config{Service: svc, Auth: BearerTokens{"tok": {Account: account, Subject: "t"}}})
	do := func(path, body, key string) (int, []map[string]any) {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var acc struct {
			Items []map[string]any `json:"items"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &acc)
		if rec.Code != http.StatusAccepted {
			t.Logf("%s: %d %s", path, rec.Code, rec.Body)
		}
		return rec.Code, acc.Items
	}
	_, sub := do("/api/v1/subnets", `{"cidrBlock":"10.6.0.0/24"}`, "batch-subnet")
	run := `{"imageId":"ami-0123456789abcdef0","instanceType":"vws.small","subnetId":"` + sub[0]["subnetId"].(string) + `","count":2}`
	code, insts := do("/api/v1/instances", run, "batch-run")
	if code != http.StatusAccepted || len(insts) != 2 {
		t.Fatalf("run %d %v", code, insts)
	}
	ids := `{"instanceIds":["` + insts[0]["instanceId"].(string) + `","` + insts[1]["instanceId"].(string) + `"]}`
	for _, action := range []string{"stop", "start", "terminate"} {
		code, items := do("/api/v1/instances/"+action, ids, "batch-"+action)
		if code != http.StatusAccepted || len(items) != 2 {
			t.Fatalf("%s: %d %v", action, code, items)
		}
	}
	if code, _ := do("/api/v1/instances/stop", `{"instanceIds":[]}`, "batch-empty"); code != http.StatusBadRequest {
		t.Fatalf("empty list: %d", code)
	}
}
