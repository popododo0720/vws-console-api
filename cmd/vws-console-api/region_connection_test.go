package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestRegionConnectionChecksMappedPools(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected mutation: %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api2/json/version":
			_, _ = w.Write([]byte(`{"data":{"version":"9.2"}}`))
		case "/api2/json/cluster/status":
			_, _ = w.Write([]byte(`{"data":[{"type":"cluster","name":"test"}]}`))
		case "/api2/json/access/permissions":
			if path := r.URL.Query().Get("path"); path != "" {
				if path != "/pool/mapped" {
					t.Errorf("unexpected managed pool: %s", path)
				}
				_, _ = w.Write([]byte(`{"data":{"/pool/mapped":{"VM.Audit":1}}}`))
			} else {
				_, _ = w.Write([]byte(`{"data":{"/":{"Sys.Audit":1,"Pool.Audit":1,"VM.Audit":1}}}`))
			}
		default:
			t.Errorf("unexpected PVE request: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	registry := store.New(store.NewMemory())
	for _, name := range []string{"pve-test-1", "pve-other-1"} {
		if _, err := registry.Regions().Create(t.Context(), store.Region{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	project := store.Project{Project: "123456789012", Pools: []store.ProjectPool{
		{Region: "pve-test-1", Pool: "mapped"}, {Region: "pve-other-1", Pool: "unrelated"},
	}}
	if _, err := registry.Projects().Put(t.Context(), project); err != nil {
		t.Fatal(err)
	}
	region := store.Region{
		Name: "pve-test-1", PVEAPIURL: srv.URL, ClusterName: "test", TokenID: "vws@pve!inventory",
		CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})),
	}
	for range 2 {
		steps := testRegionConnection(t.Context(), registry, region, "fake-secret")
		if len(steps) != 4 || steps[3].Result != resource.ConnectionFail ||
			!strings.Contains(steps[3].Message, "mapped") || !strings.Contains(steps[3].Message, "Pool.Audit") {
			t.Fatalf("mapped pool denial was not diagnosed: %+v", steps)
		}
	}
	region.Name = "pve-empty-1"
	steps := testRegionConnection(t.Context(), registry, region, "fake-secret")
	if steps[3].Result != resource.ConnectionPass {
		t.Fatalf("unrelated region mapping reached PVE: %+v", steps)
	}
}
