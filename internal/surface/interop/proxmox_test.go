package interop

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/proxmoxtest"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

func TestProxmoxInstanceWithoutSubnetOnBothSurfaces(t *testing.T) {
	b := proxmoxtest.New(t)
	regions := backend.NewStaticRegions([]backend.ProxmoxRegion{{Name: "pve-test-1"}}, nil)
	svc := cloud.New(cloud.Config{Backends: b.Set(), Capabilities: b, Regions: regions, Region: "pve-test-1"})
	account := mustParse[resource.AccountID](t, "123456789012")
	auth := iam.NewStatic("AKIDEXAMPLE", "secret", account)
	ui := console.New(console.Config{
		Service: svc, IAM: auth,
		Auth: console.BearerTokens{"token": {
			Account: account, Principal: iam.RootARN(account), Root: true, Region: "pve-test-1",
		}},
	})
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	query := ec2query.New(ec2query.Config{
		Service: svc, Authorizer: auth, Verifier: sigv4.NewVerifier(sigv4.Verifier{
			Service: sigv4.ServiceEC2, Regions: regions, Now: func() time.Time { return now },
			Auth: iam.Authenticator(auth),
		}),
	})
	for range 2 {
		res := call(t, ui, http.MethodGet, "/api/v1/instances", "", map[string]string{"Authorization": "Bearer token"})
		var page resource.Page[resource.Instance]
		if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &page) != nil ||
			len(page.Items) != 1 || page.Items[0].ReservationID.IsZero() ||
			strings.Contains(res.Body.String(), `"subnetId"`) {
			t.Fatalf("console subnetless instance: %d %s", res.Code, res.Body)
		}
		form := url.Values{"Action": {"DescribeInstances"}, "Version": {ec2query.Version}}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
			"http://127.0.0.1:8081/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := sigv4.Sign(req, cred, sigv4.ServiceEC2, "pve-test-1", now); err != nil {
			t.Fatal(err)
		}
		qres := httptest.NewRecorder()
		query.ServeHTTP(qres, req)
		body := qres.Body.String()
		if qres.Code != http.StatusOK || strings.Contains(body, "<subnetId") ||
			!strings.Contains(body, "<instanceId>"+page.Items[0].ID.String()+"</instanceId>") ||
			!strings.Contains(body, "<reservationId>"+page.Items[0].ReservationID.String()+"</reservationId>") {
			t.Fatalf("query subnetless instance: %d %s", qres.Code, body)
		}
	}
}
