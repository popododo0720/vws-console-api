package interop

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/backend/regionset"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
	"github.com/popododo0720/vws-console-api/internal/surface/iamquery"
	"github.com/popododo0720/vws-console-api/internal/surface/s3rest"
)

type scopeTransport struct {
	t      *testing.T
	region string
	calls  int
}

func (s *scopeTransport) Call(_ context.Context, _, _ string, input, _, _ any) error {
	s.t.Helper()
	scope, ok := input.(backend.Scope)
	if !ok || scope.Region != s.region || scope.Account.String() != "123456789012" {
		s.t.Fatalf("regional transport received %#v", input)
	}
	s.calls++
	return nil
}

func TestVerifiedRegionReachesRegionsetOnEC2AndS3(t *testing.T) {
	now := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)
	account := mustParse[resource.AccountID](t, "123456789012")
	auth := iam.NewStatic("AKIDEXAMPLE", "secret", account)
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	regions := backend.NewStaticRegions([]backend.ProxmoxRegion{{Name: "pve-test-1"}}, nil)
	for range 2 {
		transport := &scopeTransport{t: t, region: "pve-test-1"}
		set, err := regionset.New(regions, func(context.Context, backend.ProxmoxRegion) (regionclient.Transport, error) {
			return transport, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		svc := cloud.New(cloud.Config{Backends: set, Regions: regions})
		for _, service := range []sigv4.Service{sigv4.ServiceEC2, sigv4.ServiceS3} {
			v := sigv4.NewVerifier(sigv4.Verifier{
				Service: service, Regions: regions, Auth: iam.Authenticator(auth), Now: func() time.Time { return now },
			})
			handler := s3rest.New(s3rest.Config{Service: svc, Verifier: v, Authorizer: auth})
			path := "/"
			if service == sigv4.ServiceEC2 {
				handler = ec2query.New(ec2query.Config{Service: svc, Verifier: v, Authorizer: auth})
				path = "/?Action=DescribeVolumes&Version=" + ec2query.Version
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
			if err := sigv4.Sign(req, cred, service, transport.region, now); err != nil {
				t.Fatal(err)
			}
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusOK {
				t.Fatalf("%s: %d %s", service, res.Code, res.Body)
			}
		}
		if transport.calls != 2 {
			t.Fatalf("regional calls = %d, want 2", transport.calls)
		}
	}
}

func TestIAMAndSTSIgnoreRegionalCatalog(t *testing.T) {
	now := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)
	account := mustParse[resource.AccountID](t, "123456789012")
	auth := iam.NewStatic("AKIDEXAMPLE", "secret", account)
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	v := func(service sigv4.Service) *sigv4.Verifier {
		return sigv4.NewVerifier(sigv4.Verifier{
			Service: service, Auth: iam.Authenticator(auth), Now: func() time.Time { return now },
		})
	}
	handler := iamquery.New(iamquery.Config{
		Admin: iam.NewFake(), Authorizer: auth, IAM: v(sigv4.ServiceIAM), STS: v(sigv4.ServiceSTS),
	})
	for _, region := range []string{"pve-test-1", "pve-unknown-1", "xx-fake-1", "ap-northeast-2"} {
		for _, service := range []sigv4.Service{sigv4.ServiceIAM, sigv4.ServiceSTS} {
			path := "/?Action=ListUsers&Version=" + iamquery.IAMVersion
			if service == sigv4.ServiceSTS {
				path = "/?Action=GetCallerIdentity&Version=" + iamquery.STSVersion
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
			if err := sigv4.Sign(req, cred, service, region, now); err != nil {
				t.Fatal(err)
			}
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusOK || strings.Contains(res.Body.String(), "credential scope rejected") {
				t.Errorf("%s/%s: %d %s", service, region, res.Code, res.Body)
			}
		}
	}
}
