package proxmox

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

func TestPVEQueryInventory(t *testing.T) {
	s := scenario()
	s.Nodes = append(s.Nodes, pvefake.Node{Name: "pve2"})
	s.Roles[0].Privs = append(s.Roles[0].Privs, "Pool.Audit")
	s.VMs = []pvefake.VM{
		{VMID: 100, Node: "pve1", Pool: "123456789012", Status: "running", Config: map[string]string{
			"smbios1": "uuid=5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10", "cores": "1", "sockets": "1", "memory": "1024",
		}},
	}
	c, f := serve(t, s)
	reg := registration()
	reg.Region.Name = resource.RegionName
	reg.Region.Zones = []backend.Zone{{Letter: "a", Nodes: []string{"pve1"}}, {Letter: "b", Nodes: []string{"pve2"}}}
	b, err := New(t.Context(), c, reg, RegionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.SetNodeOnline("pve2", false); err != nil {
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
	for _, tc := range []struct {
		action, zone, want string
		status             int
	}{
		{"DescribeInstances", "", "<instanceType>vws.small</instanceType>", http.StatusOK},
		{"DescribeAvailabilityZones", "vws-1b", "<zoneState>impaired</zoneState>", http.StatusOK},
		{"DescribeAvailabilityZones", "unknown", "InvalidParameterValue", http.StatusBadRequest},
		{"DescribeRegions", "", "<regionName>vws-1</regionName>", http.StatusOK},
	} {
		t.Run(tc.action+tc.zone, func(t *testing.T) {
			form := url.Values{"Action": {tc.action}, "Version": {ec2query.Version}}
			if tc.zone != "" {
				form.Set("ZoneName.1", tc.zone)
			}
			r := httptest.NewRequestWithContext(t.Context(),
				http.MethodPost, "http://localhost/", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if err := sigv4.Sign(r, cred, sigv4.ServiceEC2, resource.RegionName, now); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			t.Logf("%s: HTTP %d %s", tc.action, w.Code, w.Body)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
}
