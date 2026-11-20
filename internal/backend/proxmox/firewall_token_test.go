package proxmox

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const firewallSecret = "firewall-secret"

func firewallScenario(privs ...string) pvefake.Scenario {
	s := scenario()
	s.Roles = append(s.Roles, pvefake.Role{ID: "VWSFirewall", Privs: privs})
	s.Tokens = append(s.Tokens, pvefake.Token{
		ID: "vws@pve!firewall", Secret: firewallSecret, ACL: []pvefake.ACE{{Path: "/", Role: "VWSFirewall"}},
	})
	return s
}

func TestFirewallTokenScope(t *testing.T) {
	for _, tc := range []struct {
		name   string
		privs  []string
		config RegionConfig
		ok     bool
	}{
		{"exact", []string{"Sys.Modify", "Sys.Audit"}, RegionConfig{}, true},
		{"extra privilege", []string{"Sys.Modify", "Sys.Audit", "VM.Audit"}, RegionConfig{}, false},
		{"no Sys.Modify", []string{"Sys.Audit"}, RegionConfig{}, false},
		{"no Sys.Audit", []string{"Sys.Modify"}, RegionConfig{}, false},
		{"read only region", []string{"Sys.Modify", "Sys.Audit"}, RegionConfig{ReadOnly: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := pvefake.New(firewallScenario(tc.privs...))
			checkLaunch(t, err)
			srv := httptest.NewServer(f)
			defer srv.Close()
			c, err := pveclient.New(pveclient.Config{
				BaseURL: srv.URL, TokenID: "vws@pve!firewall", Secret: firewallSecret, HTTPClient: srv.Client(),
			})
			checkLaunch(t, err)
			err = checkFirewall(t.Context(), c, tc.config)
			var sc *selfCheckError
			if tc.ok != (err == nil) || !tc.ok && (!errors.As(err, &sc) || sc.check != "firewall_privileges") {
				t.Fatalf("checkFirewall = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestFirewallTokenRegistration(t *testing.T) {
	dir := t.TempDir()
	s := firewallScenario("Sys.Modify", "Sys.Audit")
	s.Roles = append(s.Roles, pvefake.Role{ID: "Broad", Privs: []string{"Sys.Modify", "Sys.Audit", "VM.Audit"}})
	s.Tokens = append(s.Tokens, pvefake.Token{
		ID: "vws@pve!broad", Secret: "broad-secret", ACL: []pvefake.ACE{{Path: "/", Role: "Broad"}},
	})
	f, err := pvefake.New(s)
	checkLaunch(t, err)
	pve := httptest.NewServer(f)
	defer pve.Close()
	writeFixture(t, filepath.Join(dir, "region.yaml"), []byte("read_only: false\n"))
	state := filepath.Join(dir, "state")
	conn, err := Open(filepath.Join(dir, "region.yaml"), "pve-test-1", state, pve.URL, pve.Client())
	checkLaunch(t, err)
	register := func(fields map[string]string) error {
		input := map[string]any{"region": "pve-test-1", "cluster_name": "test", "tokenId": "vws@pve!inventory"}
		for k, v := range fields {
			input[k] = v
		}
		data, err := json.Marshal(input)
		checkLaunch(t, err)
		return conn.Register(t.Context(), data)
	}
	registered := func() bool {
		_, err := os.Stat(filepath.Join(state, registrationFile))
		return err == nil
	}
	err = register(map[string]string{
		"token": "fake-secret", "firewallTokenId": "vws@pve!broad", "firewallToken": "broad-secret",
	})
	if e := resource.AsError(err); e.Message != "registration self-check failed: firewall_privileges" || registered() {
		t.Fatalf("broad firewall token: %v, registered=%v", err, registered())
	}
	err = register(map[string]string{"token": "fake-secret", "firewallTokenId": "vws@pve!firewall"})
	if resource.AsError(err).Field != "firewallToken" {
		t.Fatalf("first firewall registration without its token: %v", err)
	}
	checkLaunch(t, register(map[string]string{
		"token": "fake-secret", "firewallTokenId": "vws@pve!firewall", "firewallToken": firewallSecret,
	}))
	b, err := conn.Check(t.Context())
	if err != nil || b.firewall == nil {
		t.Fatalf("registered firewall token: backend=%v err=%v", b, err)
	}
	checkLaunch(t, register(map[string]string{"firewallTokenId": "vws@pve!firewall"}))
	if b, err := conn.Check(t.Context()); err != nil || b.firewall == nil {
		t.Fatalf("reused firewall token: %v", err)
	}
	err = register(map[string]string{"firewallTokenId": "vws@pve!other"})
	if resource.AsError(err).Field != "firewallToken" {
		t.Fatalf("changed firewall token id without its token: %v", err)
	}
	checkLaunch(t, register(nil))
	data, err := os.ReadFile(filepath.Join(state, registrationFile))
	checkLaunch(t, err)
	if b, err := conn.Check(t.Context()); err != nil || b.firewall != nil || bytes.Contains(data, []byte(firewallSecret)) {
		t.Fatalf("removed firewall token: firewall=%v err=%v", b.firewall, err)
	}
}
