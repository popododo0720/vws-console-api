package main

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

func TestRegisteredAvailabilityZonesFollowEditsAndRestart(t *testing.T) {
	registry := store.New(store.NewMemory())
	region, err := registry.Regions().Create(t.Context(), store.Region{
		Name: "pve-live-1", Zones: []store.Zone{{Letter: "a"}, {Letter: "b"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	cred := sigv4.Credential{AccessKey: "key", Secret: "secret", Account: account}
	auth := iam.NewStatic(cred.AccessKey, cred.Secret, account)
	type zone struct {
		Name   string `xml:"zoneName"`
		ID     string `xml:"zoneId"`
		State  string `xml:"zoneState"`
		Region string `xml:"regionName"`
		Group  string `xml:"groupName"`
		Long   string `xml:"groupLongName"`
		Border string `xml:"networkBorderGroup"`
	}
	for restart := range 2 {
		catalog := inventoryCatalog{RegionCatalog: registry.Catalog()}
		h := ec2query.New(ec2query.Config{
			Service:    cloud.New(cloud.Config{Capabilities: catalog, Regions: catalog}),
			Authorizer: auth,
			Verifier: sigv4.NewVerifier(sigv4.Verifier{
				Service: sigv4.ServiceEC2, Regions: catalog, Auth: iam.Authenticator(auth),
			}),
		})
		request := func(params url.Values, want int) []zone {
			t.Helper()
			params.Set("Action", "DescribeAvailabilityZones")
			params.Set("Version", ec2query.Version)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost/?"+params.Encode(), nil)
			if err := sigv4.Sign(req, cred, sigv4.ServiceEC2, region.Name, time.Now()); err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != want {
				t.Fatalf("restart %d: status %d, want %d: %s", restart, rec.Code, want, rec.Body)
			}
			var response struct {
				Zones []zone `xml:"availabilityZoneInfo>item"`
			}
			if err := xml.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			return response.Zones
		}
		for _, letters := range [][]string{{"a", "b"}, {"c"}, {}} {
			region.Zones = nil
			var want []zone
			for _, letter := range letters {
				region.Zones = append(region.Zones, store.Zone{Letter: letter})
				name := region.Name + letter
				want = append(want, zone{name, name, "available", region.Name, region.Name, "VWS " + region.Name, region.Name})
			}
			region, err = registry.Regions().Update(t.Context(), region)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if got := request(url.Values{}, http.StatusOK); !reflect.DeepEqual(got, want) {
					t.Errorf("restart %d zones: got %+v, want %+v", restart, got, want)
				}
			}
			if len(want) != 0 {
				for _, filter := range []string{"region-name", "group-name"} {
					if got := request(url.Values{
						"Filter.1.Name": {filter}, "Filter.1.Value.1": {region.Name},
					}, http.StatusOK); !reflect.DeepEqual(got, want) {
						t.Errorf("%s filter: got %+v, want %+v", filter, got, want)
					}
				}
			}
			request(url.Values{"ZoneName.1": {"vws-1a"}}, http.StatusBadRequest)
			if len(letters) == 1 {
				request(url.Values{"ZoneName.1": {region.Name + "a"}}, http.StatusBadRequest)
			}
		}
	}
}
