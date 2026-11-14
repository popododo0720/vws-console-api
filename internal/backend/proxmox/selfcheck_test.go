package proxmox

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
)

func TestStartupMutationTokenScope(t *testing.T) {
	for _, tc := range []struct {
		path, privilege string
	}{
		{"/", "VM.PowerMgmt"},
		{"/vms", "VM.Config.Future"},
		{"/pool/managed", "Permissions.Modify"},
		{"/pool/managed", "Pool.Allocate"},
		{"/", "Sys.Modify"},
		{"/nodes/pve1", "Sys.Modify"},
		{"/storage/local", "Datastore.Allocate"},
		{"/pool/managed", "VM.Migrate"},
		{"/vms/100", "VM.Snapshot.Rollback"},
		{"/pool/managed", "VM.GuestAgent.Unrestricted"},
	} {
		for _, propagate := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s%s/propagate=%v", tc.path, tc.privilege, propagate), func(t *testing.T) {
				s := scenario()
				s.Roles = append(s.Roles, pvefake.Role{ID: "Danger", Privs: []string{tc.privilege}})
				s.Tokens[0].ACL = append(s.Tokens[0].ACL,
					pvefake.ACE{Path: tc.path, Role: "Danger", Propagate: &propagate})
				c, _ := serve(t, s)
				b, err := New(t.Context(), c, registration(), RegionConfig{})
				if err == nil || b != nil || !strings.Contains(err.Error(), tc.privilege) ||
					!strings.Contains(err.Error(), tc.path) {
					t.Fatalf("backend=%v error=%v", b, err)
				}
			})
		}
	}
	t.Run("scoped operator", func(t *testing.T) {
		s := scenario()
		s.Roles = append(s.Roles, pvefake.Role{ID: "VWSRegionOperator", Privs: []string{
			"VM.Audit", "VM.Allocate", "VM.Clone", "VM.PowerMgmt", "VM.Config.CPU", "VM.Config.Memory",
			"VM.Config.Disk", "VM.Config.Network", "VM.Config.Cloudinit", "VM.Config.Options",
			"VM.Config.HWType", "VM.Snapshot", "VM.Console", "VM.GuestAgent.Audit", "Pool.Audit",
		}}, pvefake.Role{ID: "VWSTemplateReader", Privs: []string{"VM.Audit", "VM.Clone"}},
			pvefake.Role{ID: "VWSStorageUser", Privs: []string{"Datastore.Audit", "Datastore.AllocateSpace"}},
			pvefake.Role{ID: "VWSNetUser", Privs: []string{"SDN.Use", "SDN.Audit"}})
		s.Tokens[0].ACL = append(s.Tokens[0].ACL,
			pvefake.ACE{Path: "/pool/managed", Role: "VWSRegionOperator"},
			pvefake.ACE{Path: "/pool/vws-images", Role: "VWSTemplateReader"},
			pvefake.ACE{Path: "/vms/100", Role: "VWSTemplateReader"},
			pvefake.ACE{Path: "/storage/local", Role: "VWSStorageUser"},
			pvefake.ACE{Path: "/sdn/zones/localnetwork/vmbr0", Role: "VWSNetUser"})
		c, _ := serve(t, s)
		for range 2 {
			b, err := New(t.Context(), c, registration(), RegionConfig{})
			if err != nil || b == nil {
				t.Fatalf("scoped operator backend=%v error=%v", b, err)
			}
		}
	})
}

func startupClient(t *testing.T, handler http.HandlerFunc) *pveclient.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := pveclient.New(pveclient.Config{
		BaseURL: srv.URL, TokenID: "vws@pve!inventory",
		Secret: "test-secret", HTTPClient: srv.Client(), Backoff: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestStartupPermissionInventory(t *testing.T) {
	for _, body := range []string{`{}`, `{"data":null}`, `{"data":{}}`} {
		t.Run(body, func(t *testing.T) {
			c := startupClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/access/permissions") {
					fmt.Fprint(w, body)
					return
				}
				fmt.Fprint(w, `{"data":[]}`)
			})
			b, err := New(t.Context(), c, registration(), RegionConfig{ReadOnly: true})
			if body == `{"data":{}}` {
				if err != nil || b == nil {
					t.Fatalf("explicit empty inventory: backend=%v err=%v", b, err)
				}
			} else if b != nil || err == nil || !strings.Contains(err.Error(), "check token permissions") ||
				errors.Unwrap(err) == nil {
				t.Fatalf("missing inventory: backend=%v err=%v", b, err)
			}
		})
	}
}

func TestStartupFailureContext(t *testing.T) {
	for _, path := range []string{"/access/permissions", "/cluster/status", "/cluster/resources"} {
		t.Run(path, func(t *testing.T) {
			calls := 0
			c := startupClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, path) {
					calls++
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprint(w, `{"message":"denied"}`)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/access/permissions") {
					fmt.Fprint(w, `{"data":{}}`)
					return
				}
				fmt.Fprint(w, `{"data":[]}`)
			})
			cfg := RegionConfig{ReadOnly: true, Storages: map[string]string{"gp3": "local"}}
			b, err := New(t.Context(), c, registration(), cfg)
			var he *pveclient.HTTPError
			if b != nil || !errors.As(err, &he) || he.Status != 403 || !strings.Contains(err.Error(), path) || calls != 1 {
				t.Fatalf("backend=%v err=%v calls=%d", b, err, calls)
			}
		})
	}
}

func TestStartupDeadline(t *testing.T) {
	c := startupClient(t, func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	b, err := New(ctx, c, registration(), RegionConfig{ReadOnly: true})
	if b != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("backend=%v err=%v elapsed=%s", b, err, time.Since(start))
	}
}
