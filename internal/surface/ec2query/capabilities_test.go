package ec2query

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

type noAddresses struct{}

func (noAddresses) RegionCapabilities(_ context.Context, region string) (resource.RegionCapabilities, error) {
	return resource.RegionCapabilities{Region: region, Kind: resource.RegionKindProxmox}, nil
}

func TestRegionWithoutAnActionAnswersAsEC2(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	svc := cloud.New(cloud.Config{
		Backends:     fake.New(fake.Options{Now: func() time.Time { return now }}).Set(),
		Capabilities: noAddresses{},
	})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	h := New(Config{
		Service:    svc,
		Authorizer: iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account),
		Verifier: sigv4.NewVerifier(sigv4.Verifier{
			Service: sigv4.ServiceEC2,
			Regions: backend.DefaultRegions(),
			Now:     func() time.Time { return now },
			Auth:    iam.Authenticator(iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account)),
		}),
	})
	form := url.Values{"Action": {"AllocateAddress"}, "Version": {Version}, "Domain": {"vpc"}}
	res := signed(t, h, cred, now, form.Encode())
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "<Code>UnsupportedOperation</Code>") {
		t.Fatalf("AllocateAddress: %d %s", res.Code, res.Body)
	}
	form = url.Values{"Action": {"DescribeAddresses"}, "Version": {Version}}
	res = signed(t, h, cred, now, form.Encode())
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "<addressesSet></addressesSet>") {
		t.Fatalf("DescribeAddresses: %d %s", res.Code, res.Body)
	}
}
