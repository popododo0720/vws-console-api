package proxmox

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestManagedPoolChecks(t *testing.T) {
	for _, pool := range []string{"mapped", "images", "default"} {
		for _, failure := range []string{"", "Pool.Audit", "VM.Audit", "absent"} {
			t.Run(pool+"/"+failure, func(t *testing.T) {
				s := scenario()
				s.Pools = []string{"mapped", "images", "default"}
				s.Roles[0].Privs = append(s.Roles[0].Privs, "Pool.Audit")
				if failure == "absent" {
					for i, name := range s.Pools {
						if name == pool {
							s.Pools = append(s.Pools[:i], s.Pools[i+1:]...)
							break
						}
					}
				} else if failure != "" {
					var privileges []string
					if failure == "Pool.Audit" {
						privileges = []string{"VM.Audit"}
					} else {
						privileges = []string{"Pool.Audit"}
					}
					s.Roles = append(s.Roles, pvefake.Role{ID: "Specific", Privs: privileges})
					s.Tokens[0].ACL = append(s.Tokens[0].ACL, pvefake.ACE{Path: "/pool/" + pool, Role: "Specific"})
				}
				cfg := RegionConfig{
					ReadOnly: true, Pools: map[string]string{"project": "mapped", "fallback": "default", "alias": "mapped"},
					DefaultProject: "fallback", Templates: TemplateConfig{Pool: "images"},
				}
				c, _ := serve(t, s)
				for range 2 {
					b, err := New(t.Context(), c, registration(), cfg)
					if failure == "" {
						if err != nil || b == nil {
							t.Fatalf("startup: %v", err)
						}
					} else if err == nil || b != nil || !strings.Contains(err.Error(), pool) ||
						failure != "absent" && !strings.Contains(err.Error(), failure) {
						t.Fatalf("startup must name pool %s and failure %s: %v", pool, failure, err)
					}
				}
			})
		}
	}
}

func TestPoolSelfCheckDoesNotExposeUpstreamBody(t *testing.T) {
	for _, failPath := range []string{"/access/permissions", "/pools/managed"} {
		t.Run(failPath, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				path := strings.TrimPrefix(r.URL.Path, "/api2/json")
				if path == failPath && (path != "/access/permissions" || r.URL.Query().Get("path") != "") {
					http.Error(w, "upstream-secret-canary", http.StatusForbidden)
					return
				}
				if path == "/access/permissions" {
					_, _ = w.Write([]byte(`{"data":{"/pool/managed":{"Pool.Audit":1,"VM.Audit":1}}}`))
				} else {
					_, _ = w.Write([]byte(`{"data":[]}`))
				}
			}))
			defer srv.Close()
			c := &Connection{
				config:   RegionConfig{ReadOnly: true, Pools: map[string]string{"project": "managed"}},
				endpoint: srv.URL, transport: srv.Client(),
			}
			_, err := c.check(t.Context(), registrationSnapshot{
				Region: "pve-test-1", ClusterName: "test", TokenID: "vws@pve!inventory", Token: "fake-secret",
			})
			e := resource.AsError(err)
			if e == nil || e.Code != resource.CodeUnavailable || !strings.Contains(e.Message, `pool "managed"`) ||
				strings.Contains(err.Error(), "upstream-secret-canary") ||
				resource.RegistrationFailureMessage(err) != e.Message {
				t.Fatalf("unsafe or missing pool reason: %v", err)
			}
		})
	}
}
