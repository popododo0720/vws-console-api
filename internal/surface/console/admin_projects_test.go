package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
)

const projectPath = "/api/v1/admin/projects/123456789012"

func TestAdminProjectsListsOnlyStoredMappings(t *testing.T) {
	e, g, auditLog := projectFixture(t)
	const path = "/api/v1/admin/projects"
	empty := projectCall(t, e, "GET", path, nil, "", 200)
	if strings.TrimSpace(empty.Body.String()) != `{"projects":[]}` {
		t.Fatalf("empty list: %s", empty.Body)
	}
	projectCall(t, e, "GET", projectPath, nil, "", 200)
	if got := projectCall(t, e, "GET", path, nil, "", 200); got.Body.String() != empty.Body.String() {
		t.Fatal("detail default appeared in stored mappings")
	}
	for _, v := range []store.Project{
		{
			Project:     "222222222222",
			Pools:       []store.ProjectPool{{Region: "pve-lab-1", Pool: "shared"}},
			AWSAccounts: []string{"123456789012"},
		},
		{Project: "111111111111"},
	} {
		if _, err := g.Projects().Put(t.Context(), v); err != nil {
			t.Fatal(err)
		}
	}
	want := `{"projects":[{"project":"111111111111","pools":[],"awsAccounts":[]},` +
		`{"project":"222222222222","pools":[{"region":"pve-lab-1","pool":"shared"}],"awsAccounts":["123456789012"]}]}`
	for range 2 {
		h := e.h.(*handler)
		e.h = New(Config{Registry: g, Auth: h.auth, IAM: h.iam})
		if got := projectCall(t, e, "GET", path, nil, "", 200); strings.TrimSpace(got.Body.String()) != want {
			t.Fatalf("sorted stored mappings after handler recreation: %s", got.Body)
		}
	}
	projectCall(t, e, "GET", path+"?ignored=1", nil, "", 400)
	e.h.(*handler).registry = nil
	projectCall(t, e, "GET", path, nil, "", 503)
	if auditLog.Len() != 0 {
		t.Fatal("read wrote audit entries")
	}
}

func TestAdminProjectsSkipsUndecodableRecords(t *testing.T) {
	e, _, app, _ := accountFixture(t)
	b := store.NewMemory()
	for key, value := range map[string]string{
		"projects/111111111111": `{"project":"111111111111","pools":null,"awsAccounts":null}`,
		"projects/corrupt":      "private-undecodable-project-value",
		"projects/bad-arrays":   `{"pools":42}`,
	} {
		if _, err := b.Create(t.Context(), key, []byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	e.h.(*handler).registry = store.New(b)
	rec := projectCall(t, e, "GET", "/api/v1/admin/projects", nil, "", 200)
	if strings.TrimSpace(rec.Body.String()) != `{"projects":[{"project":"111111111111","pools":[],"awsAccounts":[]}]}` {
		t.Fatalf("list with corrupt records: %s", rec.Body)
	}
	var entry map[string]any
	if err := json.Unmarshal(app.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if entry["level"] != "WARN" || entry["msg"] != "admin registry skipped undecodable records" ||
		entry["count"] != float64(2) || len(entry) != 4 {
		t.Fatalf("warning must contain only time, level, message and count: %s", app)
	}
}

type failedProjectListStore struct{ store.Backend }

func (failedProjectListStore) List(context.Context, string) ([]store.Entry, error) {
	return nil, errors.New("https://user:token@private.invalid/secret")
}

func TestAdminProjectsRegistryFailureIsSafe(t *testing.T) {
	e, _, _ := projectFixture(t)
	e.h.(*handler).registry = store.New(failedProjectListStore{Backend: store.NewMemory()})
	rec := projectCall(t, e, "GET", "/api/v1/admin/projects", nil, "", 503)
	if !strings.Contains(rec.Body.String(), "admin registry read failed") ||
		strings.Contains(rec.Body.String(), "private.invalid") || strings.Contains(rec.Body.String(), "token") {
		t.Fatalf("registry diagnostics escaped: %s", rec.Body)
	}
}

func projectFixture(t *testing.T) (loginEnv, *store.Registry, *bytes.Buffer) {
	t.Helper()
	e, g, _, auditLog := accountFixture(t)
	e.h.(*handler).regionPool = func(ctx context.Context, _, _ string) (bool, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second {
			return false, errors.New("pool check has no bounded deadline")
		}
		return true, nil
	}
	return e, g, auditLog
}

func projectBody(pool string) map[string]any {
	pools := []store.ProjectPool{}
	if pool != "" {
		pools = append(pools, store.ProjectPool{Region: "pve-lab-1", Pool: pool})
	}
	return map[string]any{"pools": pools, "awsAccounts": []string{"123456789012"}}
}

func projectCall(
	t *testing.T, e loginEnv, method, path string, body any, match string, want int,
) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rec := e.do(t, method, path, string(data), map[string]string{"Authorization": "Bearer tok", "If-Match": match})
	if rec.Code != want || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s %s: %d %s, want %d", method, path, rec.Code, rec.Body, want)
	}
	t.Logf("%s %s If-Match=%s -> %d ETag=%s %s", method, path, match, rec.Code, rec.Header().Get("ETag"), rec.Body)
	return rec
}

func TestProjectMappingDefaultsPoolToProject(t *testing.T) {
	e, g, auditLog := projectFixture(t)
	if _, err := g.Regions().Create(t.Context(), store.Region{Name: "pve-other-1"}); err != nil {
		t.Fatal(err)
	}
	rec := projectCall(t, e, "GET", projectPath, nil, "", 200)
	var got store.Project
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Project != "123456789012" || len(got.Pools) != 2 || got.Pools[0].Region != "pve-lab-1" ||
		got.Pools[1].Region != "pve-other-1" || got.AWSAccounts == nil || len(got.AWSAccounts) != 0 ||
		rec.Header().Get("ETag") != `"0"` || auditLog.Len() != 0 {
		t.Fatalf("default mapping: %+v %s", got, rec.Header())
	}
	for _, pool := range got.Pools {
		if pool.Pool != got.Project {
			t.Fatalf("default pool: %+v", pool)
		}
	}
	if _, err := g.Projects().Get(t.Context(), got.Project); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GET persisted a default: %v", err)
	}
}

func TestProjectMappingDefaultsSkipUndecodableRegions(t *testing.T) {
	e, _, app, auditLog := accountFixture(t)
	b := store.NewMemory()
	g := store.New(b)
	if _, err := g.Regions().Create(t.Context(), store.Region{Name: "pve-valid-1"}); err != nil {
		t.Fatal(err)
	}
	const badKey, badValue = "regions/pve-corrupt-1", "private-undecodable-region-value"
	if _, err := b.Create(t.Context(), badKey, []byte(badValue)); err != nil {
		t.Fatal(err)
	}
	e.h.(*handler).registry = g
	rec := projectCall(t, e, "GET", projectPath, nil, "", 200)
	var got store.Project
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Pools) != 1 || got.Pools[0] != (store.ProjectPool{Region: "pve-valid-1", Pool: "123456789012"}) ||
		rec.Header().Get("ETag") != `"0"` || auditLog.Len() != 0 {
		t.Fatalf("default mapping with a corrupt region: %+v", got)
	}
	lines := strings.Split(strings.TrimSpace(app.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("warning lines=%d, want 1", len(lines))
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatal(err)
	}
	if entry["level"] != "WARN" || entry["msg"] != "admin registry skipped undecodable records" ||
		entry["count"] != float64(1) || len(entry) != 4 {
		t.Fatalf("warning must contain only time, level, message and count: %s", app)
	}
	for _, private := range []string{badKey, "pve-corrupt-1", badValue, "pve-valid-1", "123456789012"} {
		if strings.Contains(app.String(), private) {
			t.Fatal("warning contains a registry key, value or identifier")
		}
	}
}

func TestProjectMappingRefusesUnregisteredAccount(t *testing.T) {
	e, g, _ := projectFixture(t)
	body := projectBody("shared")
	body["awsAccounts"] = []string{"999999999999"}
	rec := projectCall(t, e, "PUT", projectPath, body, `"0"`, 400)
	if !strings.Contains(rec.Body.String(), "999999999999") {
		t.Fatal("unregistered account was not named")
	}
	body = projectBody("shared")
	body["pools"] = []store.ProjectPool{{Region: "pve-unknown-1", Pool: "shared"}}
	rec = projectCall(t, e, "PUT", projectPath, body, `"0"`, 400)
	if !strings.Contains(rec.Body.String(), "pve-unknown-1") {
		t.Fatal("unregistered region was not named")
	}
	if _, err := g.Projects().Get(t.Context(), "123456789012"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("failed validation saved a mapping")
	}
}

func TestProjectMappingPoolIsExclusive(t *testing.T) {
	e, _, _ := projectFixture(t)
	first := projectCall(t, e, "PUT", projectPath, projectBody("shared"), `"0"`, 200)
	second := "/api/v1/admin/projects/222222222222"
	conflict := projectCall(t, e, "PUT", second, projectBody("shared"), `"0"`, 409)
	if !strings.Contains(conflict.Body.String(), "shared") || !strings.Contains(conflict.Body.String(), "pve-lab-1") {
		t.Fatal("exclusive pool conflict lost the region or pool")
	}
	projectCall(t, e, "PUT", projectPath, projectBody(""), first.Header().Get("ETag"), 200)
	projectCall(t, e, "PUT", second, projectBody("shared"), `"0"`, 200)
}

func TestProjectMappingStaleIfMatchConflicts(t *testing.T) {
	e, _, _ := projectFixture(t)
	first := projectCall(t, e, "PUT", projectPath, projectBody("first"), `"0"`, 200)
	projectCall(t, e, "PUT", projectPath, projectBody("second"), `"0"`, 409)
	projectCall(t, e, "PUT", projectPath, projectBody("first"), `"0"`, 409)
	got := projectCall(t, e, "GET", projectPath, nil, "", 200)
	if got.Body.String() != first.Body.String() || got.Header().Get("ETag") != first.Header().Get("ETag") {
		t.Fatal("stale write changed the mapping")
	}
}

func TestProjectMappingAuditsEachChangeOnce(t *testing.T) {
	e, _, auditLog := projectFixture(t)
	first := projectCall(t, e, "PUT", projectPath, projectBody("first"), `"0"`, 200)
	second := projectCall(t, e, "PUT", projectPath, projectBody("second"), first.Header().Get("ETag"), 200)
	projectCall(t, e, "PUT", projectPath, projectBody("second"), second.Header().Get("ETag"), 200)
	projectCall(t, e, "PUT", projectPath, projectBody("bad"), `"0"`, 409)
	projectCall(t, e, "GET", projectPath, nil, "", 200)
	lines := strings.Split(strings.TrimSpace(auditLog.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("audit lines=%d, want one per PUT", len(lines))
	}
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if entry["action"] != "vws:AdminMapProject" || entry["destination"] != "admin" ||
			entry["account"] != e.account.String() || entry["principal_arn"] == "" ||
			entry["source_ip"] != "192.0.2.10" || entry["result"] == "" || len(entry) != 14 ||
			!strings.Contains(line, `"resource_ids":["123456789012"]`) {
			t.Fatalf("audit entry: %s", line)
		}
	}
	rec := projectCall(t, e, "GET", "/api/v1/admin/permissions", nil, "", 200)
	if !strings.Contains(rec.Body.String(), "vws:AdminMapProject") {
		t.Fatal("mapping permission not advertised")
	}
}

func TestProjectMappingRestartAndIdempotentRetry(t *testing.T) {
	e, g, auditLog := projectFixture(t)
	first := projectCall(t, e, "PUT", projectPath, projectBody("shared"), `"0"`, 200)
	h := e.h.(*handler)
	e.h = New(Config{
		Registry: g, Auth: h.auth, IAM: h.iam, AdminKey: h.adminKey,
		Audit: h.audit, RegionPool: h.regionPool,
	})
	get := projectCall(t, e, "GET", projectPath, nil, "", 200)
	if get.Body.String() != first.Body.String() || get.Header().Get("ETag") != first.Header().Get("ETag") {
		t.Fatal("restart changed the mapping")
	}
	for range 2 {
		body := projectBody("shared")
		body["project"] = "123456789012"
		retry := projectCall(t, e, "PUT", projectPath, body, get.Header().Get("ETag"), 200)
		if retry.Header().Get("ETag") != get.Header().Get("ETag") || retry.Body.String() != get.Body.String() {
			t.Fatal("idempotent PUT changed version or mapping")
		}
	}
	if strings.Count(auditLog.String(), "\n") != 3 {
		t.Fatal("retry bypassed or duplicated audit")
	}
}

func TestProjectMappingRejectsMaliciousInput(t *testing.T) {
	e, g, _ := projectFixture(t)
	for _, id := range []string{"bad", "12345678901", "1234567890123", "12345678901x", "123456789012%2Fextra"} {
		projectCall(t, e, "GET", "/api/v1/admin/projects/"+id, nil, "", 400)
		projectCall(t, e, "PUT", "/api/v1/admin/projects/"+id, projectBody("valid"), `"0"`, 400)
	}
	for _, body := range []string{
		`null`, `{}`, `{"pools":null,"awsAccounts":[]}`, `{"pools":[],"awsAccounts":null}`,
		`{"pools":[],"awsAccounts":[],"unknown":true}`, `{} {}`,
		`{"project":"999999999999","pools":[],"awsAccounts":[]}`,
		`{"pools":[{"region":"pve-lab-1","pool":"a"},{"region":"pve-lab-1","pool":"b"}],"awsAccounts":[]}`,
		`{"pools":[{"region":"pve-lab-1","pool":"../secret"}],"awsAccounts":[]}`,
		`{"pools":[],"awsAccounts":["123456789012","123456789012"]}`,
	} {
		if rec := e.do(t, "PUT", projectPath, body,
			map[string]string{"Authorization": "Bearer tok", "If-Match": `"0"`}); rec.Code != 400 {
			t.Fatalf("malicious body accepted: %d %s", rec.Code, rec.Body)
		}
	}
	rec := e.do(t, "PUT", projectPath, strings.Repeat(" ", 1<<20)+"{}",
		map[string]string{"Authorization": "Bearer tok", "If-Match": `"0"`})
	if rec.Code != 413 {
		t.Fatalf("oversized body: %d", rec.Code)
	}
	projectCall(t, e, "PUT", projectPath, projectBody("valid"), "", 400)
	projectCall(t, e, "PUT", projectPath, projectBody("valid"), "*", 409)
	projectCall(t, e, "PUT", projectPath+"?ignored=1", projectBody("valid"), `"0"`, 400)
	if _, err := g.Projects().Get(t.Context(), "123456789012"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("malicious input wrote a mapping")
	}
}

func TestProjectMappingWritesRequireRootKeyAndCSRF(t *testing.T) {
	e, _, auditLog := projectFixture(t)
	user, _ := e.login(t)
	denied := e.do(t, "PUT", projectPath, "{}", map[string]string{CSRFHeader: csrfToken(user.Value)}, user)
	if denied.Code != 403 {
		t.Fatalf("non-root write: %d", denied.Code)
	}
	if err := e.root.SetPassword(t.Context(), "root password 9"); err != nil {
		t.Fatal(err)
	}
	login := e.do(t, "POST", "/api/v1/auth/login",
		`{"account":"123456789012","userName":"root","password":"root password 9"}`, nil)
	root := cookie(t, login, SessionCookie)
	if rec := e.do(t, "PUT", projectPath, "{}", nil, root); rec.Code != 403 {
		t.Fatal("root cookie bypassed CSRF")
	}
	data, err := json.Marshal(projectBody("valid"))
	if err != nil {
		t.Fatal(err)
	}
	rec := e.do(t, "PUT", projectPath, string(data),
		map[string]string{CSRFHeader: csrfToken(root.Value), "If-Match": `"0"`}, root)
	if rec.Code != 200 {
		t.Fatalf("root with CSRF: %d %s", rec.Code, rec.Body)
	}
	if strings.Count(auditLog.String(), "\n") != 3 {
		t.Fatal("gate failures or successful cookie write were not audited once")
	}
	key := e.h.(*handler).adminKey
	e.h.(*handler).adminKey = nil
	projectCall(t, e, "PUT", projectPath, projectBody("valid"), rec.Header().Get("ETag"), 503)
	projectCall(t, e, "GET", projectPath, nil, "", 200)
	e.h.(*handler).adminKey = key
	e.h.(*handler).audit = nil
	projectCall(t, e, "PUT", projectPath, projectBody("different"), rec.Header().Get("ETag"), 503)
	unchanged := projectCall(t, e, "GET", projectPath, nil, "", 200)
	if unchanged.Header().Get("ETag") != rec.Header().Get("ETag") {
		t.Fatal("write without audit logging changed the mapping")
	}
}

func TestProjectMappingTransportErrorsAreSafe(t *testing.T) {
	for _, cause := range []error{
		&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED},
		context.DeadlineExceeded,
		errors.New("https://user:token@private.invalid/secret"),
	} {
		e, g, _ := projectFixture(t)
		e.h.(*handler).regionPool = func(context.Context, string, string) (bool, error) { return false, cause }
		rec := projectCall(t, e, "PUT", projectPath, projectBody("valid"), `"0"`, 503)
		if !strings.Contains(rec.Body.String(), "region transport failed") ||
			strings.Contains(rec.Body.String(), "token") || strings.Contains(rec.Body.String(), "private.invalid") {
			t.Fatal("transport diagnostics escaped")
		}
		if _, err := g.Projects().Get(t.Context(), "123456789012"); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("unreachable pool check saved a mapping")
		}
	}
}
