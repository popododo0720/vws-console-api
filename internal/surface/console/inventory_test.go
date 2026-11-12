package console

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/backend/regionset"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type inventoryTransport func(context.Context, string, string, backend.Scope, any, any) error

func (f inventoryTransport) Call(ctx context.Context, service, method string, s, q, dst any) error {
	return f(ctx, service, method, s.(backend.Scope), q, dst)
}

func inventoryRoutes() []string {
	return []string{
		"instances", "volumes", "snapshots", "vpcs", "subnets",
		"security-groups", "addresses", "key-pairs", "images", "buckets",
	}
}

func inventoryHandler(t *testing.T, set backend.Set, catalog backend.RegionCatalog) http.Handler {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{
		Service: cloud.New(cloud.Config{Backends: set, Regions: catalog}),
		IAM:     iam.NewStatic("AKIDEXAMPLE", "secret", account),
		Auth: BearerTokens{"tok": {
			Account: account, Principal: iam.RootARN(account), Root: true,
		}},
	})
}

func inventoryGET(t *testing.T, h http.Handler, route, region string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/"+route, nil)
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("X-Vws-Region", region)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func inventoryItem(dst any, s backend.Scope) {
	page := reflect.ValueOf(dst).Elem()
	items := page.FieldByName("Items")
	items.Set(reflect.MakeSlice(items.Type(), 1, 1))
	item := items.Index(0)
	item.FieldByName("OwnerID").Set(reflect.ValueOf(s.Account))
	if state := item.FieldByName("State"); state.IsValid() {
		switch state.Type() {
		case reflect.TypeFor[resource.InstanceState]():
			state.Set(reflect.ValueOf(resource.InstanceRunning))
		case reflect.TypeFor[resource.SubnetState]():
			state.Set(reflect.ValueOf(resource.SubnetAvailable))
		default:
			state.SetString("available")
		}
	}
}

func TestConsoleInventoryMetadata(t *testing.T) {
	catalog := backend.NewStaticRegions([]backend.ProxmoxRegion{
		{Name: "pve-a-1"}, {Name: "pve-b-1"}, {Name: "pve-c-1"},
	}, nil)
	for _, scenario := range []struct {
		name, region, stale, failed string
		addressesOnly               bool
	}{
		{name: "one", region: "pve-a-1"},
		{name: "all", region: "all"},
		{name: "one stale", region: "pve-a-1", stale: "pve-a-1"},
		{name: "all stale", region: "all", stale: "pve-b-1"},
		{name: "partial stale", region: "all", stale: "pve-b-1", failed: "pve-c-1"},
		{name: "derived stale", region: "all", stale: "pve-b-1", addressesOnly: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			for restart := range 2 {
				set, err := regionset.New(catalog, func(
					context.Context, backend.ProxmoxRegion,
				) (regionclient.Transport, error) {
					return inventoryTransport(func(_ context.Context, _, method string, s backend.Scope, _, dst any) error {
						if s.Region == scenario.failed {
							return errors.New("https://credential-canary:token-canary@internal.invalid/private")
						}
						inventoryItem(dst, s)
						if s.Region == scenario.stale && (!scenario.addressesOnly || method == "DescribeAddresses") {
							if stale, ok := dst.(interface{ SetStale(bool) }); ok {
								stale.SetStale(true)
							}
						}
						return nil
					}), nil
				})
				if err != nil {
					t.Fatal(err)
				}
				h := inventoryHandler(t, set, catalog)
				for _, route := range inventoryRoutes() {
					t.Run(route, func(t *testing.T) {
						var first string
						for retry := range 2 {
							rec := inventoryGET(t, h, route, scenario.region)
							if rec.Code != http.StatusOK {
								t.Fatalf("restart %d retry %d: %d %s", restart, retry, rec.Code, rec.Body)
							}
							var page struct {
								Items   []map[string]json.RawMessage `json:"items"`
								Partial []resource.Partial           `json:"partial"`
							}
							if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
								t.Fatal(err)
							}
							want := []string{"pve-a-1"}
							if scenario.region == "all" {
								want = []string{"pve-a-1", "pve-b-1"}
								if scenario.failed == "" {
									want = append(want, "pve-c-1")
								}
							}
							var got []string
							for _, item := range page.Items {
								var region string
								if err := json.Unmarshal(item["region"], &region); err != nil {
									t.Fatal(err)
								}
								got = append(got, region)
							}
							if !slices.Equal(got, want) {
								t.Fatalf("regions = %v, want %v", got, want)
							}
							if scenario.failed == "" {
								if strings.Contains(rec.Body.String(), `"partial"`) {
									t.Fatalf("unexpected partial: %s", rec.Body)
								}
							} else if !reflect.DeepEqual(page.Partial, []resource.Partial{
								{Region: scenario.failed, Error: "region unavailable"},
							}) {
								t.Fatalf("partial = %+v", page.Partial)
							}
							wantStale := ""
							if scenario.stale != "" && (!scenario.addressesOnly || route == "instances" || route == "addresses") {
								wantStale = "true"
							}
							if got := rec.Header().Get("X-Vws-Stale"); got != wantStale {
								t.Fatalf("stale = %q, want %q", got, wantStale)
							}
							for _, canary := range []string{"credential-canary", "token-canary", "internal.invalid", "https://"} {
								if strings.Contains(rec.Body.String(), canary) {
									t.Fatalf("unsafe response: %s", rec.Body)
								}
							}
							if retry == 0 {
								first = rec.Body.String()
							} else if rec.Body.String() != first {
								t.Fatal("retry changed inventory")
							}
						}
					})
				}
			}
		})
	}
}

func TestFakeInventoryHasNoPartialOrStale(t *testing.T) {
	h := inventoryHandler(t, fake.New(fake.Options{}).Set(), backend.DefaultRegions())
	for _, region := range []string{"", "all"} {
		for _, route := range inventoryRoutes() {
			rec := inventoryGET(t, h, route, region)
			if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"partial"`) ||
				rec.Header().Get("X-Vws-Stale") != "" {
				t.Fatalf("%s: %d %s headers %v", route, rec.Code, rec.Body, rec.Header())
			}
			var page struct {
				Items []struct {
					Region string `json:"region"`
				} `json:"items"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
			for _, item := range page.Items {
				if item.Region != resource.RegionName {
					t.Fatalf("%s: fake region = %q", route, item.Region)
				}
			}
		}
	}
}

func TestInventoryPartialRejectsRawErrors(t *testing.T) {
	rec := httptest.NewRecorder()
	writeInventory(rec, resource.Page[resource.Instance]{Partial: []resource.Partial{
		{Region: "pve-a-1", Error: "https://credential-canary:token-canary@internal.invalid"},
		{Region: "pve-b-1", Error: "region timed out"},
	}})
	want := `{"items":[],"partial":[{"region":"pve-a-1","error":"region unavailable"},` +
		`{"region":"pve-b-1","error":"region timed out"}]}` + "\n"
	if rec.Body.String() != want {
		t.Fatalf("unsafe partial: %s", rec.Body)
	}
}
