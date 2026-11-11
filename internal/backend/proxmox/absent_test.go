package proxmox

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

func TestPVEAbsentFeatureReads(t *testing.T) {
	c, _ := serve(t, scenario())
	reg := registration()
	reg.Region.Name = resource.RegionName
	b, err := New(t.Context(), c, reg, RegionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	account, _ := resource.Parse[resource.AccountID]("123456789012")
	cred := sigv4.Credential{AccessKey: "AKID", Secret: "secret", Account: account}
	now := time.Now().UTC()
	auth := iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account)
	h := ec2query.New(ec2query.Config{
		Service: cloud.New(cloud.Config{Backends: b.Set(), Capabilities: b}), Authorizer: auth,
		Verifier: sigv4.NewVerifier(sigv4.Verifier{
			Service: sigv4.ServiceEC2, Regions: backend.DefaultRegions(),
			Now: func() time.Time { return now }, Auth: iam.Authenticator(auth),
		}),
	})
	for _, tc := range []struct{ action, key, value, want string }{
		{"DescribeAddresses", "", "", "<addressesSet></addressesSet>"},
		{"DescribeRouteTables", "RouteTableId.1", "rtb-01234567", "<routeTableSet></routeTableSet>"},
		{
			"DescribeVolumesModifications", "VolumeId.1", "vol-0123456789abcdef0",
			"<volumeModificationSet></volumeModificationSet>",
		},
	} {
		t.Run(tc.action, func(t *testing.T) {
			form := url.Values{"Action": {tc.action}, "Version": {ec2query.Version}}
			if tc.key != "" {
				form.Set(tc.key, tc.value)
			}
			r := httptest.NewRequestWithContext(t.Context(),
				http.MethodPost, "http://localhost/", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if err := sigv4.Sign(r, cred, sigv4.ServiceEC2, resource.RegionName, now); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
}
