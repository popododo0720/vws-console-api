package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/secret"
	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// testRegionRoute posts an unsaved region test and returns the daemon request
// the console built and the steps it answered.
func testRegionRoute(
	t *testing.T, name string, send func(context.Context, string, json.RawMessage) ([]resource.ConnectionStep, error),
) (map[string]any, []resource.ConnectionStep, string) {
	t.Helper()
	registry := store.New(store.NewMemory())
	for _, region := range []string{"pve-test-1", "pve-other-1"} {
		if _, err := registry.Regions().Create(t.Context(), store.Region{Name: region}); err != nil {
			t.Fatal(err)
		}
	}
	project := store.Project{Project: "123456789012", Pools: []store.ProjectPool{
		{Region: "pve-test-1", Pool: "mapped"}, {Region: "pve-other-1", Pool: "unrelated"},
	}}
	if _, err := registry.Projects().Put(t.Context(), project); err != nil {
		t.Fatal(err)
	}
	key, err := secret.New("test", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var sent map[string]any
	var endpoint string
	h := New(Config{
		Registry: registry, AdminKey: key, Auth: BearerTokens{"root": {Root: true}},
		RegionConnection: func(ctx context.Context, to string, data json.RawMessage) ([]resource.ConnectionStep, error) {
			endpoint = to
			if err := json.Unmarshal(data, &sent); err != nil {
				t.Error(err)
			}
			return send(ctx, to, data)
		},
	})
	body, err := json.Marshal(map[string]any{
		"name": name, "clusterName": "test", "pveApiUrls": []string{"https://pve1:8006"},
		"caPem": testCA(), "tokenId": "vws@pve!inventory", "regionEndpoint": "https://region.example:8443",
		"tokenSecret": "fake-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/admin/regions/test",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer root")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("test route: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Steps []resource.ConnectionStep `json:"steps"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if sent != nil && endpoint != "https://region.example:8443" {
		t.Errorf("the request went to %s, not the region endpoint", endpoint)
	}
	return sent, out.Steps, rec.Body.String()
}

func passing() []resource.ConnectionStep {
	return []resource.ConnectionStep{
		{Name: "tls", Result: resource.ConnectionPass, Message: "PVE TLS certificate verified"},
		{Name: "version", Result: resource.ConnectionPass, Message: "PVE version read succeeded"},
		{Name: "cluster_name", Result: resource.ConnectionPass, Message: "cluster_name accepted"},
		{Name: "privileges", Result: resource.ConnectionPass, Message: "token privileges are read-only"},
	}
}

func TestRegionConnectionSendsTheCandidateAndMappedPoolsToTheDaemon(t *testing.T) {
	for region, pools := range map[string][]any{"pve-test-1": {"mapped"}, "pve-empty-1": {}} {
		sent, steps, _ := testRegionRoute(t, region,
			func(context.Context, string, json.RawMessage) ([]resource.ConnectionStep, error) {
				return passing(), nil
			})
		if sent["region"] != region || sent["cluster_name"] != "test" || sent["token"] != "fake-secret" ||
			sent["tokenId"] != "vws@pve!inventory" || len(sent["pveApiUrls"].([]any)) != 1 {
			t.Errorf("%s: candidate sent to the daemon: %v", region, sent)
		}
		if got, _ := json.Marshal(sent["pools"]); string(got) != mustJSON(t, pools) {
			t.Errorf("%s: pools = %s, want %v", region, got, pools)
		}
		if len(steps) != 5 || steps[4].Name != "regionapi" || steps[4].Result != resource.ConnectionSkipped &&
			steps[4].Result != resource.ConnectionFail {
			t.Errorf("%s: steps = %+v", region, steps)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRegionConnectionWithoutAWorkingDaemonFailsTheFirstStepClearly(t *testing.T) {
	const canary = "credential-canary-5521"
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"unreachable": {
			errors.New(canary + " dial tcp 10.0.0.9:8443"),
			"PVE checks run in the region daemon, which did not answer: region transport failed",
		},
		"refused": {
			&resource.Error{Code: resource.CodeInvalidArgument, Field: "token", Message: canary},
			"region daemon refused the test request",
		},
		"busy": {
			&resource.Error{Code: resource.CodeUnavailable, Message: "connection test busy"},
			"region daemon, which did not answer: connection test busy",
		},
		"invalid result": {
			&resource.Error{Code: resource.CodeUnavailable, Message: "region daemon returned an invalid connection test"},
			"region daemon returned an invalid connection test",
		},
		"too large": {
			resource.TooLarge("connection test exceeds 64 KiB"),
			"region daemon refused the test request: it exceeds 64 KiB",
		},
		"route missing": {
			&resource.Error{Code: resource.CodeUnavailable, Message: resource.RegionRouteMissing},
			"the region daemon answered but has no connection test; upgrade vws-region first",
		},
		"mTLS not configured": {
			&RegionMTLSConfigError{Err: errors.New(canary)},
			"region mTLS configuration failed",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, steps, body := testRegionRoute(t, "pve-test-1",
				func(context.Context, string, json.RawMessage) ([]resource.ConnectionStep, error) { return nil, tc.err })
			if len(steps) != 5 || steps[0].Name != "tls" || steps[0].Result != resource.ConnectionFail ||
				!strings.Contains(steps[0].Message, tc.want) {
				t.Fatalf("steps = %+v, want a tls failure containing %q", steps, tc.want)
			}
			for _, step := range steps[1:] {
				if step.Result != resource.ConnectionSkipped {
					t.Errorf("step after the failure: %+v", step)
				}
			}
			if strings.Contains(body, canary) || strings.Contains(body, "fake-secret") {
				t.Fatalf("response leaks: %s", body)
			}
		})
	}
}
