package proxmox

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const backupSecret = "backup-secret"

func backupScenario() pvefake.Scenario {
	s := firewallScenario("Sys.Modify", "Sys.Audit")
	s.Roles[0].Privs = append(s.Roles[0].Privs, "Pool.Audit")
	s.Pools = []string{"managed", "parent/child"}
	s.Roles = append(s.Roles,
		pvefake.Role{ID: "BackupVM", Privs: []string{"VM.Backup"}},
		pvefake.Role{ID: "BackupStorage", Privs: []string{"Datastore.AllocateSpace"}})
	s.Tokens = append(s.Tokens, pvefake.Token{
		ID: "vws@pve!backup", Secret: backupSecret, ACL: []pvefake.ACE{
			{Path: "/pool/managed", Role: "BackupVM"},
			{Path: "/pool/parent", Role: "BackupVM"},
			{Path: "/storage/backups", Role: "BackupStorage"},
		},
	})
	return s
}

func TestBackupTokenScope(t *testing.T) {
	for _, tc := range []struct {
		name, extra, remove, want string
		readOnly                  bool
	}{
		{name: "exact set and inherited nested pool"},
		{name: "allocate refused", extra: "VM.Allocate", want: "VM.Allocate"},
		{name: "VM audit refused", extra: "VM.Audit", want: "VM.Audit"},
		{name: "system audit refused", extra: "Sys.Audit", want: "Sys.Audit"},
		{name: "managed pool missing", remove: "/pool/managed", want: "VM.Backup on /pool/managed"},
		{name: "nested pool missing", remove: "/pool/parent", want: "VM.Backup on /pool/parent/child"},
		{name: "storage missing", remove: "/storage/backups", want: "Datastore.AllocateSpace"},
		{name: "read only", readOnly: true, want: "read_only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := backupScenario()
			token := &s.Tokens[len(s.Tokens)-1]
			if tc.extra != "" {
				s.Roles = append(s.Roles, pvefake.Role{ID: "Extra", Privs: []string{tc.extra}})
				token.ACL = append(token.ACL, pvefake.ACE{Path: "/vms/999", Role: "Extra"})
			}
			if tc.remove != "" {
				var grants []pvefake.ACE
				for _, grant := range token.ACL {
					if grant.Path != tc.remove {
						grants = append(grants, grant)
					}
				}
				token.ACL = grants
			}
			f, err := pvefake.New(s)
			checkLaunch(t, err)
			srv := httptest.NewServer(f)
			defer srv.Close()
			c, err := pveclient.New(pveclient.Config{
				BaseURL: srv.URL, TokenID: token.ID, Secret: backupSecret, HTTPClient: srv.Client(),
			})
			checkLaunch(t, err)
			cfg := RegionConfig{ReadOnly: tc.readOnly, Pools: map[string]string{"project": "managed", "nested": "parent/child"}}
			err = checkBackup(t.Context(), c, cfg)
			var sc *selfCheckError
			if tc.want == "" {
				checkLaunch(t, err)
			} else if !errors.As(err, &sc) || sc.check != "backup_privileges" || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("checkBackup = %v, want backup_privileges naming %s", err, tc.want)
			}
		})
	}
}

func TestBackupTokenInput(t *testing.T) {
	for _, tc := range []struct {
		field, value, want string
	}{
		{"backupTokenId", "bad/id", "backupTokenId"},
		{"backupTokenId", "vws@pve!inventory", "backupTokenId"},
		{"backupTokenId", "vws@pve!firewall", "backupTokenId"},
		{"backupTokenId", "", "backupTokenId"},
		{"backupToken", "bad\nsecret", "backupToken"},
		{"backupToken", strings.Repeat("a", 513), "backupToken"},
		{"backupFingerprint", strings.Repeat("a", 64), "backupFingerprint"},
	} {
		t.Run(tc.field+"/"+tc.value, func(t *testing.T) {
			fields := map[string]string{
				"region": "pve-test-1", "cluster_name": "test", "tokenId": "vws@pve!inventory",
				"token": "fake-secret", "firewallTokenId": "vws@pve!firewall", "firewallToken": firewallSecret,
				"backupTokenId": "vws@pve!backup", "backupToken": backupSecret,
			}
			fields[tc.field] = tc.value
			data, err := json.Marshal(fields)
			checkLaunch(t, err)
			c := &Connection{}
			if err := c.Register(t.Context(), data); resource.AsError(err).Field != tc.want {
				t.Fatalf("invalid input: %v, want field %s", err, tc.want)
			}
		})
	}
}

func TestBackupTokenRegistration(t *testing.T) {
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
	s := backupScenario()
	s.Roles = append(s.Roles, pvefake.Role{ID: "Broad", Privs: []string{"VM.Allocate"}})
	s.Tokens = append(s.Tokens, pvefake.Token{
		ID: "vws@pve!broad", Secret: "broad-secret", ACL: []pvefake.ACE{{Path: "/pool/managed", Role: "Broad"}},
	})
	f, err := pvefake.New(s)
	checkLaunch(t, err)
	pve := httptest.NewServer(f)
	defer pve.Close()
	config := filepath.Join(dir, "region.yaml")
	writeFixture(t, config, []byte("read_only: false\npools: {project: managed, nested: parent/child}\n"))
	reg := filepath.Join(dir, "etc/pve/vws/registration.json")
	open := func() *Connection {
		conn, err := Open(config, reg, pve.URL, pve.Client())
		checkLaunch(t, err)
		conn.Helper.Path, conn.Helper.Root = helper, dir
		return conn
	}
	conn := open()
	register := func(fields map[string]string) error {
		input := map[string]string{"region": "pve-test-1", "cluster_name": "test", "tokenId": "vws@pve!inventory"}
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
		"token": "fake-secret", "backupTokenId": "vws@pve!broad", "backupToken": "broad-secret",
	})
	if resource.AsError(err).Message != "registration self-check failed: backup_privileges" || tokens() != 0 {
		t.Fatalf("broad backup token: %v, files=%d", err, tokens())
	}
	err = register(map[string]string{"token": "fake-secret", "backupTokenId": "vws@pve!backup"})
	if resource.AsError(err).Field != "backupToken" {
		t.Fatalf("first backup registration without secret: %v", err)
	}
	fields := map[string]string{
		"token": "fake-secret", "firewallTokenId": "vws@pve!firewall", "firewallToken": firewallSecret,
		"backupTokenId": "vws@pve!backup", "backupToken": backupSecret,
	}
	for range 2 {
		checkLaunch(t, register(fields))
		b, err := open().Check(t.Context())
		if err != nil || b.backup == nil || b.firewall == nil || tokens() != 3 {
			t.Fatalf("restart: backend=%v err=%v files=%d", b, err, tokens())
		}
	}
	identity, err := os.ReadFile(reg)
	checkLaunch(t, err)
	path := filepath.Join(dir, "etc/pve/priv/vws", "pve-token."+tokenFingerprint(backupSecret))
	sealed, err := os.ReadFile(path)
	checkLaunch(t, err)
	if bytes.Contains(identity, []byte(backupSecret)) || bytes.Contains(sealed, []byte(backupSecret)) {
		t.Fatal("backup secret persisted as plaintext")
	}
	for _, broken := range []string{"missing file", "mismatched file", "missing fingerprint", "plaintext identity"} {
		t.Run(broken, func(t *testing.T) {
			switch broken {
			case "missing file":
				checkLaunch(t, os.Remove(path))
			case "mismatched file":
				other, err := os.ReadFile(filepath.Join(dir, "etc/pve/priv/vws", "pve-token."+tokenFingerprint("fake-secret")))
				checkLaunch(t, err)
				writeFixture(t, path, other)
			case "missing fingerprint", "plaintext identity":
				var snapshot registrationSnapshot
				checkLaunch(t, json.Unmarshal(identity, &snapshot))
				if broken == "missing fingerprint" {
					snapshot.BackupFingerprint = ""
				} else {
					snapshot.BackupToken = backupSecret
				}
				data, err := json.Marshal(snapshot)
				checkLaunch(t, err)
				writeFixture(t, reg, data)
			}
			if _, err := open().Check(t.Context()); err == nil {
				t.Fatal("torn backup credential accepted")
			}
			writeFixture(t, path, sealed)
			writeFixture(t, reg, identity)
		})
	}
	conn = open()
	checkLaunch(t, register(map[string]string{"backupTokenId": "vws@pve!backup", "firewallTokenId": "vws@pve!firewall"}))
	b, err := conn.Check(t.Context())
	if err != nil || b.backup == nil {
		t.Fatalf("reused backup token: %v", err)
	}
	err = register(map[string]string{"backupTokenId": "vws@pve!other"})
	if resource.AsError(err).Field != "backupToken" {
		t.Fatalf("new backup id without secret: %v", err)
	}
	for range 2 {
		checkLaunch(t, register(map[string]string{"firewallTokenId": "vws@pve!firewall"}))
		b, err := open().Check(t.Context())
		if err != nil || b.backup != nil || b.firewall == nil || tokens() != 2 {
			t.Fatalf("removed backup token: backend=%v err=%v files=%d", b, err, tokens())
		}
	}
}
