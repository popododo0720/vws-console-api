package proxmox

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-lib/obs"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

func TestRegistrationSelfCheckDiagnostics(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("VWS_HEALTH_ADDR", "")
	var logs bytes.Buffer
	previous := slog.Default()
	defer slog.SetDefault(previous)
	shutdown, err := obs.Setup(t.Context(), obs.ForService("vws-region"), obs.WithOverride(func(c *obs.Config) {
		c.LogOutput = &logs
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := shutdown(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	}()
	const token = "registration-canary-secret"
	const tokenID = "canary@pve!private"
	for _, tc := range []struct {
		name, check string
		config      RegionConfig
		path        string
		status      int
	}{
		{"instance types", "instance_types", RegionConfig{InstanceTypes: map[string]InstanceTypeConfig{
			token: {Cores: 1},
		}}, "", 0},
		{"privileges", "privileges", RegionConfig{ReadOnly: true}, "", 0},
		{"permission response", "privileges", RegionConfig{}, "/access/permissions", http.StatusForbidden},
		{"cluster response", "cluster_name", RegionConfig{}, "/cluster/status", http.StatusUnauthorized},
		{"cluster mismatch", "cluster_name", RegionConfig{}, "", 0},
		{
			"storage response", "storages",
			RegionConfig{Storages: map[string]string{"gp3": "local"}},
			"/cluster/resources", http.StatusServiceUnavailable,
		},
		{"unknown storage", "storages", RegionConfig{Storages: map[string]string{"gp3": token}}, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pve := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.path != "" && strings.HasSuffix(r.URL.Path, tc.path) {
					http.Error(w, "https://"+tokenID+":"+token+"@private.example", tc.status)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/access/permissions"):
					if tc.name == "privileges" {
						_, _ = w.Write([]byte(`{"data":{"/":{"VM.PowerMgmt":1}}}`))
					} else {
						_, _ = w.Write([]byte(`{"data":{"/":{"Sys.Audit":1}}}`))
					}
				case strings.HasSuffix(r.URL.Path, "/cluster/status"):
					name := "test"
					if tc.name == "cluster mismatch" {
						name = token
					}
					_, _ = w.Write([]byte(`{"data":[{"type":"cluster","name":"` + name + `"}]}`))
				default:
					_, _ = w.Write([]byte(`{"data":[]}`))
				}
			}))
			defer pve.Close()
			c := &Connection{config: tc.config, endpoint: pve.URL, transport: pve.Client()}
			daemon := httptest.NewTLSServer(regionapi.WithRegistration(c.Register, http.NotFoundHandler()))
			defer daemon.Close()
			tlsConfig := daemon.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			tlsConfig.Certificates = daemon.TLS.Certificates
			client, err := regionapi.NewClient(daemon.URL, tlsConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			data := json.RawMessage(`{"region":"pve-test-1","cluster_name":"test","tokenId":"` +
				tokenID + `","token":"` + token + `"}`)
			want := "registration self-check failed: " + tc.check
			code := resource.CodeUnavailable
			if tc.name == "cluster mismatch" {
				want, code = "cluster_name differs from registration", resource.CodeConflict
			}
			for range 2 {
				logs.Reset()
				err := client.Register(t.Context(), data)
				if e := resource.AsError(err); e.Code != code || e.Message != want {
					t.Errorf("registration error = %v; want %s %q", err, code, want)
				}
				text := logs.String()
				if !strings.Contains(text, want) || !strings.Contains(text, `"op":"PUT /internal/v1/registration"`) {
					t.Errorf("missing classified failure or operation: %s", text)
				}
				if strings.Contains(text, token) || strings.Contains(text, tokenID) ||
					strings.Contains(text, "private.example") || strings.Contains(text, "unknown") {
					t.Errorf("unsafe diagnostic: %s", text)
				}
			}
		})
	}
}
