package sigv4

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestCredentialScopeRegionFollowsTheCatalog is #734. The credential scope
// may name any Proxmox region or AWS account region of the catalog; another
// is the usual scope rejection. The catalog is read per request, so a region
// registered while the verifier runs is accepted without a new verifier.
func TestCredentialScopeRegionFollowsTheCatalog(t *testing.T) {
	now := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)
	c := cred(t)
	regions := backend.NewStaticRegions(
		[]backend.ProxmoxRegion{{Name: "vws-1"}},
		[]backend.AWSAccount{{ID: "210987654321", AllowedRegions: []string{"ap-northeast-2"}}},
	)
	v := NewVerifier(Verifier{
		Service: ServiceEC2, Regions: regions, Now: func() time.Time { return now },
		Auth: Lookup(func(_ context.Context, key string) (Credential, bool) { return c, key == c.AccessKey }),
	})
	verify := func(region string) error {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:8080/?Action=DescribeVpcs", nil)
		r.Host = r.URL.Host
		if err := Sign(r, c, ServiceEC2, region, now); err != nil {
			t.Fatal(err)
		}
		_, err := v.Verify(r)
		return err
	}
	rejected := func(err error) bool {
		e := resource.AsError(err)
		rej, ok := RejectionOf(err)
		return ok && rej.Failure == FailureMalformed && e.Code == resource.CodeUnauthenticated &&
			e.Message == "credential scope rejected"
	}

	for _, region := range []string{"vws-1", "ap-northeast-2"} {
		if err := verify(region); err != nil {
			t.Errorf("%s: %v", region, err)
		}
	}
	for _, region := range []string{"pve-seoul-1", "us-east-1", ""} {
		if err := verify(region); !rejected(err) {
			t.Errorf("%q: got %v, want credential scope rejected", region, err)
		}
	}

	regions.AddProxmoxRegion(backend.ProxmoxRegion{Name: "pve-seoul-1", Zones: []backend.Zone{{Letter: "a"}}})
	if err := verify("pve-seoul-1"); err != nil {
		t.Errorf("pve-seoul-1 after it was added: %v", err)
	}
}

type brokenCatalog struct{}

func (brokenCatalog) ProxmoxRegions(context.Context) ([]backend.ProxmoxRegion, error) {
	return nil, errors.New("registry unavailable")
}

func (brokenCatalog) AWSAccounts(context.Context) ([]backend.AWSAccount, error) {
	return nil, errors.New("registry unavailable")
}

// A catalog that cannot be read refuses the request as internal before the
// authenticator sees it; no catalog at all accepts no region.
func TestUnreadableCatalogFailsClosed(t *testing.T) {
	now := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)
	c := cred(t)
	asked := false
	auth := Lookup(func(_ context.Context, key string) (Credential, bool) {
		asked = true
		return c, key == c.AccessKey
	})
	for _, tc := range []struct {
		name    string
		regions backend.RegionCatalog
		code    resource.Code
	}{
		{name: "unreadable", regions: brokenCatalog{}, code: resource.CodeInternal},
		{name: "nil", regions: nil, code: resource.CodeUnauthenticated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := NewVerifier(Verifier{
				Service: ServiceEC2,
				Regions: tc.regions,
				Now:     func() time.Time { return now },
				Auth:    auth,
			})
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:8080/?Action=DescribeVpcs", nil)
			r.Host = r.URL.Host
			if err := Sign(r, c, ServiceEC2, resource.RegionName, now); err != nil {
				t.Fatal(err)
			}
			_, err := v.Verify(r)
			if e := resource.AsError(err); e == nil || e.Code != tc.code {
				t.Fatalf("got %v, want code %v", err, tc.code)
			}
			if asked {
				t.Fatal("the authenticator was asked")
			}
		})
	}
}
