package regionapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestInventoryStaleHeaderAndPartialSurviveTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Scope backend.Scope `json:"scope"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.Scope.Region != "" {
			w.Header().Set("X-Vws-Stale", req.Scope.Region)
		}
		if _, err := w.Write([]byte(`{"items":[],"nextPageToken":"cursor",` +
			`"partial":[{"region":"pve-a-1","error":"region timed out"}]}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	for restart := range 2 {
		client := &Client{base: srv.URL, http: srv.Client()}
		pages := []any{
			&resource.Page[resource.Instance]{}, &resource.Page[resource.Volume]{},
			&resource.Page[resource.Snapshot]{}, &resource.Page[resource.Vpc]{},
			&resource.Page[resource.Subnet]{}, &resource.Page[resource.SecurityGroup]{},
			&resource.Page[resource.Address]{}, &resource.Page[resource.KeyPair]{},
			&resource.Page[resource.Image]{}, &resource.Page[resource.Bucket]{},
		}
		for _, header := range []string{"true", "", "false", "TRUE", "token-canary"} {
			scope := testScope(t)
			scope.Region = header
			for _, dst := range pages {
				if err := client.Call(t.Context(), "Compute", "DescribeInstances",
					scope, struct{}{}, dst); err != nil {
					t.Fatal(err)
				}
				page := reflect.ValueOf(dst).Elem()
				if stale := page.FieldByName("Stale").Bool(); stale != (header == "true") {
					t.Fatalf("restart %d %T header %q: stale = %t", restart, dst, header, stale)
				}
				if page.FieldByName("Partial").Len() != 1 ||
					page.FieldByName("NextToken").String() != "cursor" {
					t.Fatalf("%T lost metadata: %+v", dst, dst)
				}
				body, err := json.Marshal(dst)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(body), `"stale"`) {
					t.Fatalf("transport metadata reached JSON: %s", body)
				}
			}
		}
		client.Close()
	}
}
