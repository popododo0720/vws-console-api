package proxmox

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/secret"
	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

// After a failed push the saved region is not what the daemon holds: the
// daemon keeps its last working registration. A PATCH back to that
// registration needs no secret, and the daemon, not the console, decides
// whether an omitted secret is reusable. This runs the console admin API and
// the daemon registration over TLS against pvefake.
func TestAdminRegionRollbackAfterAFailedPushNeedsNoSecret(t *testing.T) {
	for _, field := range []string{"caPem", "pveApiUrls", "tokenId"} {
		t.Run(field, func(t *testing.T) {
			admin, conn, pushes := consoleWithDaemon(t, "read_only: true\n")
			fake, err := pvefake.New(pvefake.Scenario{
				Version: pvefake.Version{Version: "8.4.1", Release: "8.4"}, Cluster: "test",
				Nodes:    []pvefake.Node{{Name: "pve1"}},
				Storages: []pvefake.Storage{{Node: "pve1", Name: "local"}},
				Roles:    []pvefake.Role{{ID: "PVEAuditor", Privs: []string{"Sys.Audit", "Datastore.Audit", "VM.Audit"}}},
				Tokens: []pvefake.Token{{
					ID: "vws@pve!inventory", Secret: "working-token", ACL: []pvefake.ACE{{Path: "/", Role: "PVEAuditor"}},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			pve := httptest.NewTLSServer(fake)
			t.Cleanup(pve.Close)
			other := httptest.NewTLSServer(http.NotFoundHandler())
			t.Cleanup(other.Close)
			body := map[string]any{
				"name": "pve-test-1", "clusterName": "test", "caPem": serverCA(pve), "pveApiUrls": []string{pve.URL},
				"tokenId": "vws@pve!inventory", "tokenSecret": "working-token", "regionEndpoint": "https://region.example",
			}
			created := admin(t, "POST", body, "", 201)
			if strings.Contains(created.Body.String(), "lastError") {
				t.Fatalf("first push failed: %s", created.Body)
			}

			failing := map[string]any{"tokenSecret": "refused-token"}
			switch field {
			case "caPem":
				failing[field] = serverCA(pve) + "\n"
			case "pveApiUrls":
				failing[field] = []string{other.URL}
			case "tokenId":
				failing[field] = "vws@pve!replacement"
			}
			failed := admin(t, "PATCH", failing, created.Header().Get("ETag"), 200)
			if !strings.Contains(failed.Body.String(), "lastError") {
				t.Fatalf("the failing edit was applied: %s", failed.Body)
			}
			if _, err := conn.Check(t.Context()); err != nil {
				t.Fatalf("the daemon lost its working registration: %v", err)
			}

			// The daemon decides: a change it cannot take without a secret
			// is saved and answered with lastError, never a 400.
			refused := admin(t, "PATCH", map[string]any{"caPem": serverCA(pve) + "\n\n"}, failed.Header().Get("ETag"), 200)
			if !strings.Contains(refused.Body.String(), `"message":"resubmit tokenSecret: `) {
				t.Fatalf("a change the daemon refuses: %s", refused.Body)
			}

			rollback := map[string]any{field: body[field], "caPem": body["caPem"]}
			restored := admin(t, "PATCH", rollback, refused.Header().Get("ETag"), 200)
			if strings.Contains(restored.Body.String(), "lastError") || *pushes != 4 {
				t.Fatalf("rollback: %d pushes, %s", *pushes, restored.Body)
			}
			if _, err := conn.Check(t.Context()); err != nil {
				t.Fatalf("the rolled back registration does not work: %v", err)
			}
		})
	}
}

// A failed edit that removes an optional token id clears its metadata in the
// registry while the daemon keeps the token. Restoring the id without the
// secret reaches the daemon, which reuses its token, and later edits that omit
// the secret keep working.
func TestAdminRegionRestoredOptionalTokenNeedsNoSecret(t *testing.T) {
	for _, token := range []string{"firewallToken", "backupToken"} {
		t.Run(token, func(t *testing.T) {
			s, config := firewallScenario("Sys.Modify", "Sys.Audit"), "read_only: false\n"
			id, secret := "vws@pve!firewall", firewallSecret
			if token == "backupToken" {
				s, config = backupScenario(), "read_only: false\npools: {project: managed, nested: parent/child}\n"
				id, secret = "vws@pve!backup", backupSecret
			}
			admin, conn, pushes := consoleWithDaemon(t, config)
			fake, err := pvefake.New(s)
			if err != nil {
				t.Fatal(err)
			}
			pve := httptest.NewTLSServer(fake)
			t.Cleanup(pve.Close)
			created := admin(t, "POST", map[string]any{
				"name": "pve-test-1", "clusterName": "test", "caPem": serverCA(pve), "pveApiUrls": []string{pve.URL},
				"tokenId": "vws@pve!inventory", "tokenSecret": "fake-secret", "regionEndpoint": "https://region.example",
				token + "Id": id, token + "Secret": secret,
			}, "", 201)
			if strings.Contains(created.Body.String(), "lastError") {
				t.Fatalf("first push failed: %s", created.Body)
			}
			failed := admin(t, "PATCH", map[string]any{token + "Id": "", "tokenSecret": "refused-token"},
				created.Header().Get("ETag"), 200)
			if !strings.Contains(failed.Body.String(), "lastError") {
				t.Fatalf("the failing edit was applied: %s", failed.Body)
			}
			restored := admin(t, "PATCH", map[string]any{token + "Id": id}, failed.Header().Get("ETag"), 200)
			again := admin(t, "PATCH", map[string]any{}, restored.Header().Get("ETag"), 200)
			if body := restored.Body.String() + again.Body.String(); strings.Contains(body, "lastError") || *pushes != 4 {
				t.Fatalf("restore: %d pushes, %s", *pushes, body)
			}
			b, err := conn.Check(t.Context())
			if err != nil || token == "firewallToken" && b.firewall == nil || token == "backupToken" && b.backup == nil {
				t.Fatalf("the daemon lost its %s: %v", token, err)
			}
		})
	}
}

type adminCall func(t *testing.T, method string, body map[string]any, etag string, want int) *httptest.ResponseRecorder

// consoleWithDaemon is the console admin API whose registration pushes reach
// the region daemon's registration code through the region API over TLS. The
// fixture does not verify the client certificate.
func consoleWithDaemon(t *testing.T, regionYAML string) (adminCall, *Connection, *int) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "region.yaml")
	if err := os.WriteFile(config, []byte(regionYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	conn, err := Open(config, "pve-test-1", filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	region := httptest.NewTLSServer(regionapi.WithRegistration(conn.Register, http.NotFoundHandler()))
	t.Cleanup(region.Close)
	tlsConfig := region.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsConfig.Certificates = region.TLS.Certificates
	client, err := regionapi.NewClient(region.URL, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	key, err := secret.New("global", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	pushes := 0
	h := console.New(console.Config{
		RegionRegistration: func(ctx context.Context, _ string, data json.RawMessage) error {
			pushes++
			return client.Register(ctx, data)
		},
		Registry: store.New(store.NewMemory()),
		AdminKey: key,
		IAM:      iam.NewFake(),
		Auth:     console.BearerTokens{"tok": {Account: account, Root: true}},
	})
	call := func(t *testing.T, method string, body map[string]any, etag string, want int) *httptest.ResponseRecorder {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		path := "/api/v1/admin/regions"
		if method != http.MethodPost {
			path += "/pve-test-1"
		}
		req := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		if etag != "" {
			req.Header.Set("If-Match", etag)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s: %d %s", method, rec.Code, rec.Body)
		}
		return rec
	}
	return call, conn, &pushes
}
