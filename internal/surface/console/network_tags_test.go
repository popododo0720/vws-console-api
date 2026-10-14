package console

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestVpcAndSubnetTags(t *testing.T) {
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
	tagsAt := func(path string) map[string]string {
		t.Helper()
		rec := do(http.MethodGet, path, "", "")
		var got struct {
			Tags map[string]string `json:"tags"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
		return got.Tags
	}
	vpc := created(do(http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.5.0.0/16","tags":{"Name":"a","Cost Center":"1"}}`, "vpc-tags-1"), "vpcId")
	sub := created(do(http.MethodPost, "/api/v1/subnets", `{"cidrBlock":"10.5.1.0/24","vpcId":"`+vpc+`","tags":{"Name":"s"}}`, "sub-tags-1"), "subnetId")
	if got := tagsAt("/api/v1/vpcs/" + vpc); !maps.Equal(got, map[string]string{"Name": "a", "Cost Center": "1"}) {
		t.Fatalf("vpc tags %v", got)
	}
	if got := tagsAt("/api/v1/subnets/" + sub); !maps.Equal(got, map[string]string{"Name": "s"}) {
		t.Fatalf("subnet tags %v", got)
	}
	for path, key := range map[string]string{"/api/v1/vpcs/" + vpc + "/tags": "vt", "/api/v1/subnets/" + sub + "/tags": "st"} {
		if rec := do(http.MethodPost, path, `{"tags":{"Name":"b","env":"dev"}}`, key); rec.Code != http.StatusAccepted {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
	if got := tagsAt("/api/v1/vpcs/" + vpc); !maps.Equal(got, map[string]string{"Name": "b", "Cost Center": "1", "env": "dev"}) {
		t.Fatalf("vpc tags after tagging %v", got)
	}
	if got := tagsAt("/api/v1/subnets/" + sub); !maps.Equal(got, map[string]string{"Name": "b", "env": "dev"}) {
		t.Fatalf("subnet tags after tagging %v", got)
	}
	if rec := do(http.MethodPost, "/api/v1/vpcs/vpc-00000000000000000/tags", `{"tags":{"a":"b"}}`, "vt-missing"); rec.Code != http.StatusNotFound {
		t.Fatalf("missing vpc: %d %s", rec.Code, rec.Body)
	}
}
