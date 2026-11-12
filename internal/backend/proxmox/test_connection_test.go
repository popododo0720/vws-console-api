package proxmox

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/secret"
	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

func TestAdminProxmoxConnectionSteps(t *testing.T) {
	for _, tc := range []struct {
		name, privilege, cluster, token string
		saved, omitSecret, untrustedCA  bool
		standalone                      bool
		regionStatus                    int
		want                            []resource.ConnectionResult
	}{
		{
			"unsaved auditor", "", "test", "fake-secret", false, false, false, false, 200,
			[]resource.ConnectionResult{"PASS", "PASS", "PASS", "PASS", "PASS"},
		},
		{
			"saved auditor", "", "test", "fake-secret", true, false, false, false, 200,
			[]resource.ConnectionResult{"PASS", "PASS", "PASS", "PASS", "PASS"},
		},
		{
			"unsaved standalone", "", "test", "fake-secret", false, false, false, true, 200,
			[]resource.ConnectionResult{"PASS", "PASS", "PASS", "PASS", "PASS"},
		},
		{
			"saved standalone", "", "test", "fake-secret", true, false, false, true, 200,
			[]resource.ConnectionResult{"PASS", "PASS", "PASS", "PASS", "PASS"},
		},
		{
			"allocate privilege", "VM.Allocate", "test", "fake-secret", false, false, false, false, 200,
			[]resource.ConnectionResult{"PASS", "PASS", "PASS", "FAIL", "SKIPPED"},
		},
		{
			"unknown privilege", "Future.Privilege", "test", "fake-secret", true, false, false, false, 200,
			[]resource.ConnectionResult{"PASS", "PASS", "PASS", "FAIL", "SKIPPED"},
		},
		{
			"wrong cluster", "", "elsewhere", "fake-secret", true, false, false, false, 200,
			[]resource.ConnectionResult{"PASS", "PASS", "FAIL", "SKIPPED", "SKIPPED"},
		},
		{
			"missing saved secret", "", "test", "", true, true, false, false, 200,
			[]resource.ConnectionResult{"SKIPPED", "SKIPPED", "SKIPPED", "SKIPPED", "PASS"},
		},
		{
			"bad token", "", "test", "token-canary-762", false, false, false, false, 200,
			[]resource.ConnectionResult{"PASS", "FAIL", "SKIPPED", "SKIPPED", "SKIPPED"},
		},
		{
			"untrusted CA", "", "test", "fake-secret", false, false, true, false, 200,
			[]resource.ConnectionResult{"FAIL", "SKIPPED", "SKIPPED", "SKIPPED", "SKIPPED"},
		},
		{
			"region failure", "", "test", "fake-secret", false, false, false, false, 503,
			[]resource.ConnectionResult{"PASS", "PASS", "PASS", "PASS", "FAIL"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := scenario()
			if tc.standalone {
				s.Cluster = ""
			}
			if tc.privilege != "" {
				s.Roles[0].Privs = append(s.Roles[0].Privs, tc.privilege)
			}
			pve, err := pvefake.New(s)
			if err != nil {
				t.Fatal(err)
			}
			upstream := httptest.NewTLSServer(pve)
			defer upstream.Close()
			ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}))
			if tc.untrustedCA {
				ca = ""
			}
			var regionCalls atomic.Int32
			region := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				regionCalls.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/internal/v1/status" {
					t.Errorf("unexpected region request: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.regionStatus)
				if _, err := fmt.Fprint(w, `{"quorum":true}`); err != nil {
					t.Error(err)
				}
			}))
			region.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert}
			region.StartTLS()
			defer region.Close()
			mtls := region.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			mtls.Certificates = upstream.TLS.Certificates
			rc, err := regionapi.NewClient(region.URL, mtls)
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			g := store.New(store.NewMemory())
			v, err := g.Regions().Create(t.Context(), store.Region{
				Name: "pve-test-1", ClusterName: tc.cluster, PVEAPIURL: upstream.URL, CAPEM: ca,
				TokenID: s.Tokens[0].ID, TokenSecret: store.DescribeSecret("fake-secret"), RegionEndpoint: region.URL,
			})
			if err != nil {
				t.Fatal(err)
			}
			key, err := secret.New("test", bytes.Repeat([]byte{7}, 32))
			if err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			cfg := console.Config{
				Registry: g, AdminKey: key, Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
				Auth: console.BearerTokens{"root": {Root: true}},
				RegionConnection: func(ctx context.Context, v store.Region, token string) []resource.ConnectionStep {
					return TestConnection(ctx, ConnectionConfig{
						URL: v.PVEAPIURL, CAPEM: v.CAPEM, ClusterName: v.ClusterName,
						TokenID: v.TokenID, TokenSecret: token,
					})
				},
				RegionStatus: func(ctx context.Context, endpoint string) (resource.RegionStatus, error) {
					if endpoint != region.URL {
						t.Errorf("wrong region endpoint: %s", endpoint)
					}
					return rc.Status(ctx)
				},
			}
			path := "/api/v1/admin/regions/test"
			body := map[string]any{
				"name": v.Name, "clusterName": v.ClusterName, "pveApiUrl": v.PVEAPIURL,
				"caPem": v.CAPEM, "tokenId": v.TokenID, "regionEndpoint": v.RegionEndpoint,
			}
			if tc.saved {
				path = "/api/v1/admin/regions/" + v.Name + "/test"
				body = map[string]any{}
			}
			if !tc.omitSecret {
				body["tokenSecret"] = tc.token
			}
			data, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				req := httptest.NewRequestWithContext(t.Context(), "POST", path, bytes.NewReader(data))
				req.Header.Set("Authorization", "Bearer root")
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				console.New(cfg).ServeHTTP(rec, req)
				if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("test route: %d %s", rec.Code, rec.Body)
				}
				var result struct {
					Steps []resource.ConnectionStep `json:"steps"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if len(result.Steps) != len(tc.want) {
					t.Fatalf("steps: %s", rec.Body)
				}
				for i, name := range []string{"tls", "version", "cluster_name", "privileges", "regionapi"} {
					step := result.Steps[i]
					if step.Name != name || step.Result != tc.want[i] || step.Message == "" {
						t.Errorf("%s: %+v want %s", name, step, tc.want[i])
					}
				}
				if tc.omitSecret && !strings.Contains(rec.Body.String(), "tokenSecret is needed") {
					t.Error("missing secret was not explained")
				}
				if strings.Contains(rec.Body.String()+logs.String(), "fake-secret") ||
					strings.Contains(rec.Body.String()+logs.String(), "token-canary-762") {
					t.Error("secret leaked into response or log")
				}
				after, err := g.Regions().Get(t.Context(), v.Name)
				if err != nil || !reflect.DeepEqual(v, after) {
					t.Fatalf("registry changed: %+v %v", after, err)
				}
			}
			for _, request := range pve.Requests() {
				if !strings.HasPrefix(request, "GET ") {
					t.Errorf("test wrote to PVE: %s", request)
				}
			}
			wantCalls := int32(0)
			if tc.want[4] != resource.ConnectionSkipped {
				wantCalls = 2
			}
			if regionCalls.Load() != wantCalls {
				t.Errorf("region calls = %d, want %d", regionCalls.Load(), wantCalls)
			}
			if tc.omitSecret && len(pve.Requests()) != 0 {
				t.Error("missing secret still reached PVE")
			}
		})
	}
}
