package proxmox

import (
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestConsoleChecksPoolBeforeProxy(t *testing.T) {
	s := inventoryScenario()
	s.Roles = append(s.Roles, pvefake.Role{ID: "Console", Privs: []string{"VM.Console", "VM.Audit", "Pool.Audit"}})
	s.Tokens[0].ACL = append(s.Tokens[0].ACL, pvefake.ACE{Path: "/pool/123456789012", Role: "Console"})
	f, err := pvefake.New(s)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	client, err := pveclient.New(pveclient.Config{
		BaseURL: srv.URL, HTTPClient: srv.Client(), TokenID: s.Tokens[0].ID, Secret: pveclient.Secret(s.Tokens[0].Secret),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(t.Context(), client, registration(), RegionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := NewIDs("test")
	id, _, _ := ids.Instance(VM{UUID: option(s.VMs[0].Config["smbios1"], "uuid")})
	for _, kind := range []resource.ConsoleKind{resource.ConsoleVNC, resource.ConsoleSerial} {
		session, err := b.OpenConsole(t.Context(), inventoryScope(), id, kind)
		if err != nil {
			t.Fatal(err)
		}
		stream, err := session.Dial(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		_, reader, err := stream.NextReader()
		if err != nil {
			t.Fatal(err)
		}
		banner, err := io.ReadAll(reader)
		if err != nil || string(banner) != "RFB 003.008\n" {
			t.Fatalf("banner %q: %v", banner, err)
		}
		stream.Close()
		if _, err := session.Dial(t.Context()); resource.CodeOf(err) != resource.CodePermissionDenied {
			t.Fatalf("reused session: %v", err)
		}
	}
	pending, err := b.OpenConsole(t.Context(), inventoryScope(), id, resource.ConsoleVNC)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.MoveVM(100, "999999999999"); err != nil {
		t.Fatal(err)
	}
	before := len(f.Requests())
	_, err = b.OpenConsole(t.Context(), inventoryScope(), id, resource.ConsoleVNC)
	assertMutationNotFound(t, err, resource.KindInstance, id.String())
	_, err = pending.Dial(t.Context())
	assertMutationNotFound(t, err, resource.KindInstance, id.String())
	for _, request := range f.Requests()[before:] {
		if strings.Contains(request, "vncproxy") || strings.Contains(request, "vncwebsocket") {
			t.Fatalf("foreign pool reached console: %s", request)
		}
	}
	if len(f.PoolWriteViolations()) != 0 {
		t.Fatal("console changed pool membership")
	}
}

func TestConsoleRefusesReadOnlyAndInvalidKind(t *testing.T) {
	b, f := networkBackend(t, inventoryScenario(), RegionConfig{ReadOnly: true})
	page, err := b.DescribeInstances(t.Context(), inventoryScope(), resource.InstanceQuery{})
	if err != nil {
		t.Fatal(err)
	}
	id := page.Items[0].ID
	_, err = b.OpenConsole(t.Context(), inventoryScope(), id, resource.ConsoleVNC)
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("read-only console: %v", err)
	}
	b.cfg.ReadOnly = false
	_, err = b.OpenConsole(t.Context(), inventoryScope(), id, resource.ConsoleKind(0))
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("invalid kind: %v", err)
	}
	for _, req := range f.Requests() {
		if !strings.HasPrefix(req, "GET ") {
			t.Fatalf("refused console wrote PVE: %s", req)
		}
	}
}

func TestConnectionHonorsConsoleMode(t *testing.T) {
	s := inventoryScenario()
	s.Roles = append(s.Roles, pvefake.Role{ID: "Console", Privs: []string{"VM.Console", "VM.Audit", "Pool.Audit"}})
	s.Tokens[0].ACL = append(s.Tokens[0].ACL, pvefake.ACE{Path: "/pool/123456789012", Role: "Console"})
	_, f := serve(t, s)
	srv := httptest.NewServer(f)
	defer srv.Close()
	for _, mode := range []string{"true", "false"} {
		path := filepath.Join(t.TempDir(), "region.yaml")
		if err := os.WriteFile(path, []byte("read_only: "+mode+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := Open(path, filepath.Join(t.TempDir(), "registration.json"), srv.URL, srv.Client())
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.check(t.Context(), registrationSnapshot{
			Region: "pve-test-1", ClusterName: "test", TokenID: s.Tokens[0].ID, Token: pveclient.Secret(s.Tokens[0].Secret),
		})
		if (err != nil) != (mode == "true") {
			t.Fatalf("read_only=%s: %v", mode, err)
		}
	}
}
