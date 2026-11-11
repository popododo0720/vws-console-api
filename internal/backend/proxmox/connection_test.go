package proxmox

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func snapshot(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "registration.json")
	if err := os.WriteFile(path, []byte(`{"region":"pve-test-1","cluster_name":"test",
		"tokenId":"vws@pve!inventory","token":"fake-secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConnectionRequiresConfigRegistrationAndSelfCheck(t *testing.T) {
	dir := t.TempDir()
	reg := snapshot(t, dir)
	config := filepath.Join(dir, "region.yaml")
	if _, err := Open(config, reg, "https://unused", nil); err == nil {
		t.Fatal("accepted missing region.yaml")
	}
	for _, input := range []string{"token: do-not-echo", "pve_token: do-not-echo", "secret: do-not-echo"} {
		if err := os.WriteFile(config, []byte(input), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(config, reg, "https://unused", nil); err == nil {
			t.Fatalf("accepted secret in config: %s", input)
		}
	}
	for _, mode := range []os.FileMode{0o644, 0o640} {
		if err := os.WriteFile(config, []byte("read_only: true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(reg, mode); err != nil {
			t.Fatal(err)
		}
		c, err := Open(config, reg, "https://unused", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Check(t.Context()); err == nil {
			t.Fatalf("accepted plaintext registration with permissions %o", mode)
		}
	}
	if err := os.Chmod(reg, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reg, []byte(`{"token":"do-not-echo","extra":"do-not-echo"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Open(config, reg, "https://unused", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(t.Context()); err == nil || strings.Contains(err.Error(), "do-not-echo") {
		t.Fatalf("invalid snapshot: %v", err)
	}
}

func TestRegistrationIdentityIsBounded(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "region.yaml")
	if err := os.WriteFile(config, []byte("read_only: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(dir, "registration.json")
	write := func(region, cluster, tokenID string) {
		t.Helper()
		body := `{"region":"` + region + `","cluster_name":"` + cluster + `","tokenId":"` + tokenID +
			`","token":"do-not-echo"}`
		if err := os.WriteFile(reg, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	long := strings.Repeat("a", 64)
	for _, c := range []struct{ region, cluster, tokenID string }{
		{"", "test", "vws@pve!inventory"},
		{long, "test", "vws@pve!inventory"},
		{"PVE-Test-1", "test", "vws@pve!inventory"},
		{"pve-test-1-", "test", "vws@pve!inventory"},
		{"pve/../1", "test", "vws@pve!inventory"},
		{"pve-test-1", "", "vws@pve!inventory"},
		{"pve-test-1", long, "vws@pve!inventory"},
		{"pve-test-1", "te st", "vws@pve!inventory"},
		{"pve-test-1", "test", "vws@pve"},
		{"pve-test-1", "test", "vws@pve!" + long + "a"},
		{"pve-test-1", "test", "vws@pve!in=ventory"},
	} {
		write(c.region, c.cluster, c.tokenID)
		data, err := os.ReadFile(reg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeRegistration(data); err == nil || strings.Contains(err.Error(), "do-not-echo") {
			t.Fatalf("accepted %+v: %v", c, err)
		}
	}
	write("pve-test-1", "test", "vws@pve!inventory")
	data, err := os.ReadFile(reg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRegistration(data); err != nil {
		t.Fatalf("refused a valid registration: %v", err)
	}
}

func TestConnectionRejectsMutationTokenEvenWithoutReadOnlyConfig(t *testing.T) {
	s := scenario()
	s.Roles[0].Privs = append(s.Roles[0].Privs, "VM.PowerMgmt")
	_, fake := serve(t, s)
	pve := httptest.NewServer(fake)
	defer pve.Close()
	dir := t.TempDir()
	config := filepath.Join(dir, "region.yaml")
	if err := os.WriteFile(config, []byte("read_only: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Open(config, snapshot(t, dir), pve.URL, pve.Client())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(snapshot(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Register(t.Context(), data); err == nil || !strings.Contains(err.Error(), "self-check") {
		t.Fatalf("mutation-capable token accepted: %v", err)
	}
}
