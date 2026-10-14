package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestInstanceTypesListTheLaunchCatalog(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()})
	h := New(Config{Service: svc, Auth: BearerTokens{"tok": {Account: account, Subject: "t"}}})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/instance-types", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var page struct {
		Items []struct {
			Type      string `json:"instanceType"`
			VCPUs     int    `json:"vcpus"`
			MemoryMiB int    `json:"memoryMiB"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		t    string
		c, m int
	}{{"vws.small", 1, 1024}, {"vws.medium", 2, 4096}, {"vws.large", 4, 8192}, {"vws.xlarge", 8, 16384}}
	if len(page.Items) != len(want) {
		t.Fatalf("%s", rec.Body)
	}
	for i, w := range want {
		got := page.Items[i]
		if got.Type != w.t || got.VCPUs != w.c || got.MemoryMiB != w.m {
			t.Fatalf("item %d = %+v, want %+v", i, got, w)
		}
	}
}
