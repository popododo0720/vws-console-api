package proxmox

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
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
	helper := filepath.Join(dir, "helper")
	build := exec.CommandContext(t.Context(), "go", "test", "-c", "-o", helper, "./internal/regionhelper")
	build.Dir = "../../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("helper build: %v\n%s", err, out)
	}
	for _, name := range []string{
		"etc/pve/vws", "etc/pve/priv/vws", "etc/pve/priv/lock/vws-region", "etc/vws/credentials",
	} {
		checkLaunch(t, os.MkdirAll(filepath.Join(dir, name), 0o700))
	}
	writeFixture(t, filepath.Join(dir, "etc/vws/credentials/region-kek"), bytes.Repeat([]byte{42}, 32))
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv("VWS_HELPER_TEST_ROOT", dir)
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
	reg := filepath.Join(dir, "etc/pve/vws/registration.json")
	conn, err := Open(filepath.Join(dir, "region.yaml"), reg, pve.URL, pve.Client())
	checkLaunch(t, err)
	conn.Helper.Path, conn.Helper.Root = helper, dir
	register := func(fields map[string]string) error {
		input := map[string]any{"region": "pve-test-1", "cluster_name": "test", "tokenId": "vws@pve!inventory"}
		for k, v := range fields {
			input[k] = v
		}
		data, err := json.Marshal(input)
		checkLaunch(t, err)
		return conn.Register(t.Context(), data)
	}
	tokens := func() int {
		files, err := os.ReadDir(filepath.Join(dir, "etc/pve/priv/vws"))
		checkLaunch(t, err)
		return len(files)
	}
	err = register(map[string]string{
		"token": "fake-secret", "firewallTokenId": "vws@pve!broad", "firewallToken": "broad-secret",
	})
	if e := resource.AsError(err); e.Message != "registration self-check failed: firewall_privileges" || tokens() != 0 {
		t.Fatalf("broad firewall token: %v, %d token files", err, tokens())
	}
	err = register(map[string]string{"token": "fake-secret", "firewallTokenId": "vws@pve!firewall"})
	if resource.AsError(err).Field != "firewallToken" {
		t.Fatalf("first firewall registration without its token: %v", err)
	}
	checkLaunch(t, register(map[string]string{
		"token": "fake-secret", "firewallTokenId": "vws@pve!firewall", "firewallToken": firewallSecret,
	}))
	firewallFP := tokenFingerprint(firewallSecret)
	b, err := conn.Check(t.Context())
	if err != nil || b.firewall == nil || tokens() != 2 {
		t.Fatalf("registered firewall token: backend=%v err=%v files=%d", b, err, tokens())
	}
	if err := conn.Helper.DeleteToken(t.Context(), firewallFP); err == nil {
		t.Fatal("helper deleted the live firewall token")
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
	if b, err := conn.Check(t.Context()); err != nil || b.firewall != nil || tokens() != 1 {
		t.Fatalf("removed firewall token: firewall=%v err=%v files=%d", b.firewall, err, tokens())
	}
}
