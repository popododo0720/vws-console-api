package proxmox

import (
	"encoding/pem"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestConnectionManagedPools(t *testing.T) {
	for _, failure := range []string{"", "Pool.Audit", "VM.Audit", "absent"} {
		t.Run(failure, func(t *testing.T) {
			s := scenario()
			s.Pools = []string{"first", "second"}
			s.Roles[0].Privs = append(s.Roles[0].Privs, "Pool.Audit")
			switch failure {
			case "absent":
				s.Pools = []string{"first"}
			case "Pool.Audit", "VM.Audit":
				privileges := []string{"Pool.Audit"}
				if failure == "Pool.Audit" {
					privileges = []string{"VM.Audit"}
				}
				s.Roles = append(s.Roles, pvefake.Role{ID: "Specific", Privs: privileges})
				s.Tokens[0].ACL = append(s.Tokens[0].ACL, pvefake.ACE{Path: "/pool/second", Role: "Specific"})
			}
			pve, err := pvefake.New(s)
			if err != nil {
				t.Fatal(err)
			}
			upstream := httptest.NewTLSServer(pve)
			defer upstream.Close()
			ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}))
			for range 2 {
				steps := TestConnection(t.Context(), ConnectionConfig{
					URL: upstream.URL, CAPEM: ca, ClusterName: "test",
					TokenID: s.Tokens[0].ID, TokenSecret: s.Tokens[0].Secret,
					Pools: []string{"first", "second", "first"},
				})
				step := steps[3]
				if failure == "" {
					if step.Result != resource.ConnectionPass {
						t.Fatalf("connection: %+v", step)
					}
				} else if step.Result != resource.ConnectionFail || !strings.Contains(step.Message, "second") ||
					failure != "absent" && !strings.Contains(step.Message, failure) {
					t.Fatalf("missing pool or privilege diagnostic (%s): %+v", failure, step)
				}
			}
			for _, request := range pve.Requests() {
				if !strings.HasPrefix(request, "GET ") {
					t.Fatalf("connection wrote to PVE: %s", request)
				}
			}
		})
	}
}
