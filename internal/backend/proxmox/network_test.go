package proxmox

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

func networkBackend(t *testing.T, s pvefake.Scenario, cfg RegionConfig) (*Backend, *pvefake.Fake) {
	t.Helper()
	c, f := serve(t, s)
	reg := registration()
	reg.Region.Name = resource.RegionName
	b, err := New(t.Context(), c, reg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return b, f
}

func TestBridgeInventory(t *testing.T) {
	s := scenario()
	s.Nodes = append(s.Nodes, pvefake.Node{Name: "pve2"})
	s.Networks = []pvefake.Network{
		{Node: "pve1", Iface: "vmbr0", Type: "bridge", CIDR: "192.0.2.10/24"},
		{Node: "pve2", Iface: "vmbr0", Type: "bridge", CIDR: "192.0.2.11/24"},
		{Node: "pve1", Iface: "vmbr1", Type: "OVSBridge", CIDR: "198.51.100.10/24"},
		{Node: "pve1", Iface: "vmbr2", Type: "bridge"},
		{Node: "pve1", Iface: "eth0", Type: "eth", CIDR: "203.0.113.1/24"},
		{Node: "pve1", Iface: "", Type: "bridge"},
		{Node: "pve1", Iface: "bad-cidr", Type: "bridge", CIDR: "invalid"},
	}
	b, _ := networkBackend(t, s, RegionConfig{
		DefaultBridge: "vmbr0", Subnets: map[string]SubnetConfig{"vmbr0": {CIDR: "10.0.0.0/24"}},
	})
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	sc := backend.Scope{Account: account}
	vpcs, err := b.DescribeVpcs(t.Context(), sc, resource.VpcQuery{})
	if err != nil || len(vpcs.Items) != 4 {
		t.Fatalf("vpcs=%+v error=%v", vpcs, err)
	}
	ids, _ := NewIDs("test")
	want, _ := ids.BridgeVPC("vmbr0")
	for _, v := range vpcs.Items {
		if v.OwnerID != account || v.IsDefault != (v.ID == want) {
			t.Fatalf("vpc=%+v", v)
		}
	}
	subnets, err := b.DescribeSubnets(t.Context(), sc, resource.SubnetQuery{})
	if err != nil || len(subnets.Items) != 2 {
		t.Fatalf("subnets=%+v error=%v", subnets, err)
	}
	subnet, _ := ids.BridgeSubnet("vmbr0", "10.0.0.0/24")
	for _, sub := range subnets.Items {
		if sub.DefaultForAz != (sub.ID == subnet) || sub.OwnerID != account {
			t.Fatalf("subnet=%+v", sub)
		}
		if sub.ID == subnet && (sub.VpcID != want || sub.Cidr != "10.0.0.0/24") {
			t.Fatalf("default subnet=%+v", sub)
		}
		if sub.ID != subnet && sub.Cidr != "198.51.100.0/24" {
			t.Fatalf("host CIDR was not masked: %+v", sub)
		}
	}
	svc := cloud.New(cloud.Config{Backends: b.Set(), Capabilities: b})
	gated, err := svc.DescribeVpcs(t.Context(), resource.Caller{Account: account}, resource.VpcQuery{})
	if err != nil || len(gated.Items) != 4 {
		t.Fatalf("capability gate: %+v %v", gated, err)
	}
	first, err := b.DescribeVpcs(t.Context(), sc, resource.VpcQuery{Page: resource.PageRequest{Size: 1}})
	if err != nil || len(first.Items) != 1 || first.NextToken == "" {
		t.Fatalf("first=%+v error=%v", first, err)
	}
	second, err := b.DescribeVpcs(t.Context(), sc, resource.VpcQuery{Page: resource.PageRequest{Token: first.NextToken}})
	if err != nil || len(second.Items) != 3 || slices.ContainsFunc(second.Items, func(v resource.Vpc) bool {
		return v.ID == first.Items[0].ID
	}) {
		t.Fatalf("second=%+v error=%v", second, err)
	}
	only, err := b.DescribeSubnets(t.Context(), sc, resource.SubnetQuery{IDs: []resource.SubnetID{subnet}})
	if err != nil || len(only.Items) != 1 || only.Items[0].ID != subnet {
		t.Fatalf("selected=%+v error=%v", only, err)
	}
	if _, err := b.DescribeVpcs(t.Context(), sc, resource.VpcQuery{
		Page: resource.PageRequest{Token: "unknown"},
	}); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("invalid token: %v", err)
	}
	missing, _ := ids.BridgeVPC("missing")
	if _, err := b.DescribeVpcs(t.Context(), sc, resource.VpcQuery{
		IDs: []resource.VpcID{missing},
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("missing vpc: %v", err)
	}
	missingSubnet, _ := ids.BridgeSubnet("missing", "10.0.0.0/24")
	if _, err := b.DescribeSubnets(t.Context(), sc, resource.SubnetQuery{
		IDs: []resource.SubnetID{missingSubnet},
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("missing subnet: %v", err)
	}
}

func TestBridgeSubnetNeedsOnlineNodesToAgree(t *testing.T) {
	s := scenario()
	s.Nodes = append(s.Nodes, pvefake.Node{Name: "pve2"})
	s.Networks = []pvefake.Network{
		{Node: "pve1", Iface: "vmbr0", Type: "bridge", CIDR: "192.0.2.10/24"},
		{Node: "pve2", Iface: "vmbr0", Type: "bridge", CIDR: "198.51.100.7/24"},
		{Node: "pve1", Iface: "vmbr1", Type: "bridge", CIDR: "192.0.2.10/24"},
		{Node: "pve2", Iface: "vmbr1", Type: "bridge", CIDR: "198.51.100.7/24"},
	}
	b, f := networkBackend(t, s, RegionConfig{Subnets: map[string]SubnetConfig{"vmbr1": {CIDR: "10.1.0.0/24"}}})
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	sc := backend.Scope{Account: account}
	ids, _ := NewIDs("test")
	configured, _ := ids.BridgeSubnet("vmbr1", "10.1.0.0/24")
	subnets, err := b.DescribeSubnets(t.Context(), sc, resource.SubnetQuery{})
	if err != nil || len(subnets.Items) != 1 || subnets.Items[0].ID != configured {
		t.Fatalf("disagreeing nodes must leave vmbr0 without a subnet: %+v %v", subnets, err)
	}
	vpcs, err := b.DescribeVpcs(t.Context(), sc, resource.VpcQuery{})
	if err != nil || len(vpcs.Items) != 2 {
		t.Fatalf("vpcs=%+v error=%v", vpcs, err)
	}
	vmbr0, _ := ids.BridgeVPC("vmbr0")
	for _, v := range vpcs.Items {
		if v.ID == vmbr0 && v.Cidr != "" {
			t.Fatalf("vmbr0 took one node's CIDR: %+v", v)
		}
	}
	if err := f.SetNodeOnline("pve1", false); err != nil {
		t.Fatal(err)
	}
	after, err := b.DescribeSubnets(t.Context(), sc, resource.SubnetQuery{})
	if err != nil || len(after.Items) != 2 {
		t.Fatalf("with one node online its network is the bridge's: %+v %v", after, err)
	}
}

func TestBridgeReadFailures(t *testing.T) {
	t.Run("permission denied", func(t *testing.T) {
		s := scenario()
		no := false
		s.Tokens[0].ACL[0].Propagate = &no
		b, _ := networkBackend(t, s, RegionConfig{})
		_, err := b.DescribeVpcs(t.Context(), backend.Scope{}, resource.VpcQuery{})
		var he *pveclient.HTTPError
		if !errors.As(err, &he) || he.Status != http.StatusForbidden {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("offline node", func(t *testing.T) {
		s := scenario()
		s.Nodes = append(s.Nodes, pvefake.Node{Name: "pve2"})
		s.Networks = []pvefake.Network{{Node: "pve1", Iface: "vmbr0", Type: "bridge"}}
		b, f := networkBackend(t, s, RegionConfig{})
		if err := f.SetNodeOnline("pve2", false); err != nil {
			t.Fatal(err)
		}
		got, err := b.DescribeVpcs(t.Context(), backend.Scope{}, resource.VpcQuery{})
		if err != nil || len(got.Items) != 1 {
			t.Fatalf("online inventory=%+v error=%v", got, err)
		}
		if _, err := b.client.Network(t.Context(), "pve2"); err == nil {
			t.Fatal("offline node read succeeded")
		}
	})
	t.Run("server failure", func(t *testing.T) {
		s := scenario()
		s.Tokens[0].Secret = "test-secret"
		_, f := serve(t, s)
		c := startupClient(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/network") {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			f.ServeHTTP(w, r)
		})
		b, err := New(t.Context(), c, registration(), RegionConfig{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = b.DescribeSubnets(t.Context(), backend.Scope{}, resource.SubnetQuery{})
		var he *pveclient.HTTPError
		if !errors.As(err, &he) || he.Status != http.StatusServiceUnavailable {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestPVEQueryBridgeDefaults(t *testing.T) {
	s := scenario()
	s.Networks = []pvefake.Network{{Node: "pve1", Iface: "vmbr0", Type: "bridge", CIDR: "192.0.2.1/24"}}
	b, _ := networkBackend(t, s, RegionConfig{DefaultBridge: "vmbr0"})
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
		{"DescribeVpcs", "", "", "<isDefault>true</isDefault>"},
		{"DescribeSubnets", "", "", "<defaultForAz>true</defaultForAz>"},
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
