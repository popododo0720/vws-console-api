package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

const regionPath = "/api/v1/admin/regions"

func validRegion() map[string]any {
	return map[string]any{
		"name": "pve-test-1", "clusterName": "test", "pveApiUrl": "https://pve.example:8006",
		"tokenId": "vws@pve!inventory", "tokenSecret": "distinctive-canary-token-760",
		"regionEndpoint": "https://region.example", "zones": []store.Zone{{Letter: "a", Nodes: []string{"pve1"}}},
	}
}

func regionCall(t *testing.T, e loginEnv, method string, body any, match string, want int) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	path := regionPath
	if method != http.MethodPost {
		path += "/pve-test-1"
	}
	rec := e.do(t, method, path, string(data), map[string]string{"Authorization": "Bearer tok", "If-Match": match})
	if rec.Code != want || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s: %d %s", method, rec.Code, rec.Body)
	}
	return rec
}

func TestAdminRegionLifecycleAndCanary(t *testing.T) {
	e, g, app, auditLog := accountFixture(t)
	var pushed []map[string]any
	var mu sync.Mutex
	stub := httptest.NewTLSServer(regionapi.WithRegistration(func(_ context.Context, data json.RawMessage) error {
		var body map[string]any
		if err := json.Unmarshal(data, &body); err != nil {
			return err
		}
		mu.Lock()
		pushed = append(pushed, body)
		mu.Unlock()
		return nil
	}, http.NotFoundHandler()))
	defer stub.Close()
	config := stub.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	config.Certificates = stub.TLS.Certificates
	client, err := regionapi.NewClient(stub.URL, config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	h := e.h.(*handler)
	h.regionRegistration = func(ctx context.Context, _ string, data json.RawMessage) error {
		return client.Register(ctx, data)
	}
	h.svc = cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set(), Regions: g.Catalog()})
	post := regionCall(t, e, "POST", validRegion(), "", 201)
	original, err := g.Regions().Get(t.Context(), "pve-test-1")
	if err != nil || !original.TokenSecret.Set {
		t.Fatalf("stored metadata: %+v %v", original, err)
	}
	responses := post.Body.String()
	for _, path := range []string{regionPath, "/api/v1/regions"} {
		rec := e.do(t, "GET", path, "", map[string]string{"Authorization": "Bearer tok"})
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "pve-test-1") {
			t.Fatalf("runtime catalog %s: %d %s", path, rec.Code, rec.Body)
		}
		responses += rec.Body.String()
	}
	regionCall(t, e, "PATCH", map[string]any{}, "", 400)
	regionCall(t, e, "PATCH", map[string]any{}, `"0"`, 409)
	patch := regionCall(t, e, "PATCH", map[string]any{"zones": []store.Zone{{Letter: "b"}}},
		post.Header().Get("ETag"), 200)
	updated, err := g.Regions().Get(t.Context(), original.Name)
	mu.Lock()
	pushes := slices.Clone(pushed)
	mu.Unlock()
	if err != nil || !reflect.DeepEqual(original.TokenSecret, updated.TokenSecret) || len(pushes) != 2 {
		t.Fatalf("omitted secret or pushes: %v", err)
	}
	if pushes[0]["token"] != validRegion()["tokenSecret"] || pushes[1]["token"] != nil {
		t.Fatal("incorrect token forwarding")
	}
	regionCall(t, e, "DELETE", nil, post.Header().Get("ETag"), 409)
	regionCall(t, e, "DELETE", nil, "", 204)
	if _, err := g.Regions().Get(t.Context(), original.Name); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("delete kept region")
	}
	rec := e.do(t, "GET", "/api/v1/regions", "", map[string]string{"Authorization": "Bearer tok"})
	if rec.Code != 200 || strings.Contains(rec.Body.String(), original.Name) {
		t.Fatal("delete kept catalog entry")
	}
	responses += patch.Body.String() + rec.Body.String()
	lines := strings.Split(strings.TrimSpace(auditLog.String()), "\n")
	if len(lines) != 6 {
		t.Fatalf("audit lines=%d want 6", len(lines))
	}
	for _, line := range lines {
		if !strings.Contains(line, `"action":"Admin`) || !strings.Contains(line, `Region"`) {
			t.Fatalf("audit action: %s", line)
		}
	}
	if strings.Contains(responses+app.String()+auditLog.String(), validRegion()["tokenSecret"].(string)) {
		t.Fatal("secret escaped into response or logs")
	}
	record, err := json.Marshal(original)
	if err != nil || bytes.Contains(record, []byte(validRegion()["tokenSecret"].(string))) {
		t.Fatal("global record retained the token")
	}
}

func TestAdminRegionDeleteRefusesProjectMappings(t *testing.T) {
	e, g, app, auditLog := accountFixture(t)
	post := regionCall(t, e, "POST", validRegion(), "", 201)
	mapping, err := g.Projects().Put(t.Context(), store.Project{
		Project: "123456789012", Pools: []store.ProjectPool{{Region: "pve-test-1", Pool: "mapped"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		rec := regionCall(t, e, "DELETE", nil, post.Header().Get("ETag"), 409)
		if !strings.Contains(rec.Body.String(), "project pool mappings") {
			t.Fatalf("missing dependency explanation: %s", rec.Body)
		}
	}
	if err := g.ClaimCluster(t.Context(), "test", "pve-other-1", time.Now()); !errors.Is(err, store.ErrExists) {
		t.Fatalf("refusal released cluster claim: %v", err)
	}
	mapping.Pools = nil
	if _, err := g.Projects().Put(t.Context(), mapping); err != nil {
		t.Fatal(err)
	}
	regionCall(t, e, "DELETE", nil, post.Header().Get("ETag"), 204)
	if strings.Count(auditLog.String(), "\n") != 4 {
		t.Fatalf("expected one audit per region write: %s", auditLog)
	}
	if strings.Contains(app.String()+auditLog.String(), validRegion()["tokenSecret"].(string)) {
		t.Fatal("region secret escaped into logs")
	}
}

func TestAdminRegionValidationAndRetry(t *testing.T) {
	for _, tc := range []struct {
		field string
		value any
	}{
		{"name", "bad"},
		{"clusterName", "bad/name"},
		{"pveApiUrl", "http://insecure"},
		{"regionEndpoint", "https://user:secret@region"},
		{"caPem", "bad"},
		{"tokenId", "bad"},
		{"tokenSecret", nil},
		{"tokenSecret", ""},
		{"zones", []store.Zone{{Letter: "a", Nodes: []string{"pve1", "pve1"}}}},
		{"zones", []store.Zone{{Letter: "a", Nodes: []string{"pve1"}}, {Letter: "b", Nodes: []string{"pve1"}}}},
	} {
		e, _, _, _ := accountFixture(t)
		body := validRegion()
		body[tc.field] = tc.value
		if rec := regionCall(t, e, "POST", body, "", 400); !strings.Contains(rec.Body.String(), `"field":"`+tc.field+`"`) {
			t.Fatalf("missing field %s: %s", tc.field, rec.Body)
		}
	}
	e, g, _, auditLog := accountFixture(t)
	h := e.h.(*handler)
	h.regionRegistration = func(context.Context, string, json.RawMessage) error {
		return errors.New(validRegion()["tokenSecret"].(string))
	}
	post := regionCall(t, e, "POST", validRegion(), "", 201)
	if !strings.Contains(post.Body.String(), `"lastError"`) {
		t.Fatal("failed push not reported")
	}
	regionCall(t, e, "POST", validRegion(), "", 400)
	body := validRegion()
	body["name"] = "pve-other-1"
	if rec := regionCall(t, e, "POST", body, "", 400); !strings.Contains(rec.Body.String(), `"field":"clusterName"`) {
		t.Fatal("duplicate cluster was not rejected")
	}
	h.regionRegistration = func(context.Context, string, json.RawMessage) error {
		return resource.Invalid("token", "required")
	}
	retry := regionCall(t, e, "PATCH", map[string]any{}, post.Header().Get("ETag"), 400)
	if !strings.Contains(retry.Body.String(), `"field":"tokenSecret"`) {
		t.Fatal("missing initial token did not name tokenSecret")
	}
	h.regionRegistration = func(context.Context, string, json.RawMessage) error { return nil }
	regionCall(t, e, "PATCH", map[string]any{"tokenSecret": validRegion()["tokenSecret"]}, retry.Header().Get("ETag"), 200)
	v, err := g.Regions().Get(t.Context(), "pve-test-1")
	if err != nil || v.LastError != nil ||
		strings.Contains(auditLog.String(), validRegion()["tokenSecret"].(string)) {
		t.Fatal("retry did not clear safe failure")
	}
}

func TestAdminRegionWritesRequireRootKeyAndCSRF(t *testing.T) {
	for _, method := range []string{"POST", "PATCH", "DELETE"} {
		e, _, _, auditLog := accountFixture(t)
		user, _ := e.login(t)
		path := regionPath
		if method != "POST" {
			path += "/pve-test-1"
		}
		rec := e.do(t, method, path, "{}", map[string]string{CSRFHeader: csrfToken(user.Value)}, user)
		if rec.Code != 403 || strings.Count(auditLog.String(), "\n") != 1 {
			t.Fatalf("non-root %s: %d %s", method, rec.Code, rec.Body)
		}
		e.h.(*handler).adminKey = nil
		regionCall(t, e, method, validRegion(), `"1"`, 503)
	}
	e, _, _, _ := accountFixture(t)
	if err := e.root.SetPassword(t.Context(), "root password 9"); err != nil {
		t.Fatal(err)
	}
	login := e.do(t, "POST", "/api/v1/auth/login",
		`{"account":"123456789012","userName":"root","password":"root password 9"}`, nil)
	root := cookie(t, login, SessionCookie)
	if rec := e.do(t, "POST", regionPath, "{}", nil, root); rec.Code != 403 {
		t.Fatal("cookie write bypassed CSRF")
	}
}

func TestAdminRegionSelfCheckLastError(t *testing.T) {
	e, g, app, auditLog := accountFixture(t)
	h := e.h.(*handler)
	const message = "registration self-check failed: storages"
	stub := httptest.NewTLSServer(regionapi.WithRegistration(func(context.Context, json.RawMessage) error {
		return &resource.Error{Code: resource.CodeUnavailable, Message: message}
	}, http.NotFoundHandler()))
	defer stub.Close()
	config := stub.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	config.Certificates = stub.TLS.Certificates
	client, err := regionapi.NewClient(stub.URL, config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	h.regionRegistration = func(ctx context.Context, _ string, data json.RawMessage) error {
		return client.Register(ctx, data)
	}
	post := regionCall(t, e, "POST", validRegion(), "", 201)
	for _, response := range []string{
		post.Body.String(),
		regionCall(t, e, "PATCH", map[string]any{}, post.Header().Get("ETag"), 200).Body.String(),
	} {
		if !strings.Contains(response, message) {
			t.Errorf("operator cannot see failed check: %s", response)
		}
	}
	v, err := g.Regions().Get(t.Context(), "pve-test-1")
	if err != nil || v.LastError == nil || v.LastError.Message != message {
		t.Fatalf("persisted error = %+v, %v", v.LastError, err)
	}
	h.regionRegistration = func(context.Context, string, json.RawMessage) error {
		return &resource.Error{Code: resource.CodeUnavailable, Message: message + validRegion()["tokenSecret"].(string)}
	}
	retry := regionCall(t, e, "PATCH", map[string]any{}, `"`+fmt.Sprint(v.Version)+`"`, 200)
	if strings.Contains(retry.Body.String()+app.String()+auditLog.String(), validRegion()["tokenSecret"].(string)) {
		t.Fatal("unclassified upstream message exposed the token")
	}
}

func TestAdminRegionFirewallToken(t *testing.T) {
	e, g, _, auditLog := accountFixture(t)
	h := e.h.(*handler)
	var pushed map[string]any
	var pushErr error
	h.regionRegistration = func(_ context.Context, _ string, data json.RawMessage) error {
		pushed = nil
		if err := json.Unmarshal(data, &pushed); err != nil {
			t.Fatal(err)
		}
		return pushErr
	}
	const secret = "distinctive-firewall-canary-799"
	for field, change := range map[string]map[string]any{
		"firewallTokenSecret": {"firewallTokenSecret": secret},
		"firewallTokenId":     {"firewallTokenId": "vws@pve!inventory", "firewallTokenSecret": secret},
	} {
		body := validRegion()
		maps.Copy(body, change)
		if rec := regionCall(t, e, "POST", body, "", 400); !strings.Contains(rec.Body.String(), `"field":"`+field+`"`) {
			t.Fatalf("invalid %s accepted: %s", field, rec.Body)
		}
	}
	body := validRegion()
	body["firewallTokenId"], body["firewallTokenSecret"] = "vws@pve!firewall", secret
	post := regionCall(t, e, "POST", body, "", 201)
	if pushed["firewallTokenId"] != "vws@pve!firewall" || pushed["firewallToken"] != secret ||
		strings.Contains(post.Body.String(), secret) ||
		!strings.Contains(post.Body.String(), `"firewallTokenSecret":{"set":true`) {
		t.Fatalf("pushed=%v response=%s", pushed, post.Body)
	}
	patch := regionCall(t, e, "PATCH", map[string]any{}, post.Header().Get("ETag"), 200)
	if _, sent := pushed["firewallToken"]; sent || pushed["firewallTokenId"] != "vws@pve!firewall" {
		t.Fatalf("omitted firewall secret pushed=%v", pushed)
	}
	pushErr = resource.Invalid("firewallToken", "required")
	retry := regionCall(t, e, "PATCH", map[string]any{}, patch.Header().Get("ETag"), 400)
	if !strings.Contains(retry.Body.String(), `"field":"firewallTokenSecret"`) {
		t.Fatalf("daemon refusal did not name firewallTokenSecret: %s", retry.Body)
	}
	pushErr = nil
	regionCall(t, e, "PATCH", map[string]any{"firewallTokenId": ""}, retry.Header().Get("ETag"), 200)
	v, err := g.Regions().Get(t.Context(), "pve-test-1")
	if _, sent := pushed["firewallTokenId"]; sent || err != nil || v.FirewallTokenSecret.Set ||
		strings.Contains(auditLog.String(), secret) {
		t.Fatalf("removed firewall token: pushed=%v region=%+v err=%v", pushed, v, err)
	}
}
