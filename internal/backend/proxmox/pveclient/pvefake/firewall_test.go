package pvefake_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
)

func TestFirewallGroupWritesNeedSysModify(t *testing.T) {
	f, err := pvefake.New(pvefake.Scenario{
		Version: pvefake.Version{Version: "9.2", Release: "9.2"}, Cluster: "test", Nodes: []pvefake.Node{{Name: "pve1"}},
		Roles: []pvefake.Role{
			{ID: "PVEAuditor", Privs: []string{"Sys.Audit", "VM.Audit"}},
			{ID: "VWSFirewall", Privs: []string{"Sys.Modify", "Sys.Audit"}},
		},
		Tokens: []pvefake.Token{
			{ID: "vws@pve!region", Secret: "k", ACL: []pvefake.ACE{{Path: "/", Role: "PVEAuditor"}}},
			{ID: "vws@pve!firewall", Secret: "k", ACL: []pvefake.ACE{{Path: "/", Role: "VWSFirewall"}}},
		},
		FirewallGroups: []pvefake.FirewallGroup{{Group: "admin", Comment: "made in the PVE UI"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	client := func(id string) *pveclient.Client {
		c, err := pveclient.New(pveclient.Config{BaseURL: srv.URL, TokenID: id, Secret: "k", HTTPClient: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	region, firewall := client("vws@pve!region"), client("vws@pve!firewall")
	for _, err := range []error{
		region.CreateFirewallGroup(t.Context(), "web", "vws"), region.DeleteFirewallGroup(t.Context(), "admin"),
	} {
		if e := (*pveclient.HTTPError)(nil); !errors.As(err, &e) || e.Status != http.StatusForbidden {
			t.Fatalf("region token wrote a group: %v", err)
		}
	}
	for _, bad := range []string{"x", "1web", "a-group-name-longer", "../admin"} {
		if err := firewall.CreateFirewallGroup(t.Context(), bad, ""); err == nil {
			t.Fatalf("invalid group name %q accepted", bad)
		}
	}
	if err := firewall.CreateFirewallGroup(t.Context(), "web", "vws:v=1 name=web tier"); err != nil {
		t.Fatal(err)
	}
	if err := firewall.CreateFirewallGroup(t.Context(), "web", "again"); err == nil {
		t.Fatal("duplicate group created")
	}
	groups, err := region.FirewallGroups(t.Context())
	if err != nil || len(groups) != 2 || groups[1].Group != "web" || groups[1].Comment != "vws:v=1 name=web tier" {
		t.Fatalf("groups=%+v err=%v", groups, err)
	}
	if err := firewall.DeleteFirewallGroup(t.Context(), "web"); err != nil {
		t.Fatal(err)
	}
	if err := firewall.DeleteFirewallGroup(t.Context(), "web"); err == nil {
		t.Fatal("deleted a missing group")
	}
}
