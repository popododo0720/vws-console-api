package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type loginEnv struct {
	clock   *time.Time
	h       http.Handler
	account resource.AccountID
	fake    *iam.Fake
	root    *iam.Static
}

func newLoginEnv(t *testing.T) loginEnv {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	clock := new(time.Time)
	*clock = time.Date(2026, 10, 14, 8, 0, 0, 0, time.UTC)
	f := iam.NewFake()
	root := iam.NewStatic("AKIDEXAMPLE", "secret", account)
	client := iam.WithRoot(root, f)
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()})
	rootCaller := resource.Caller{Account: account, Subject: "console-token", Principal: iam.RootARN(account), Root: true}
	h := New(Config{Service: svc, IAM: client, Auth: BearerTokens{"tok": rootCaller}, Now: func() time.Time { return *clock }})
	ctx := t.Context()
	if _, err := f.CreateUser(ctx, account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateLoginProfile(ctx, account, "bob", "correct horse 1"); err != nil {
		t.Fatal(err)
	}
	read := `{"Statement":[{"Effect":"Allow","Action":["ec2:Describe*","s3:ListAllMyBuckets"],"Resource":"*"}]}`
	if err := f.PutInlinePolicy(ctx, account, iam.EntityUser, "bob", "read", read, ""); err != nil {
		t.Fatal(err)
	}
	return loginEnv{clock: clock, h: h, account: account, fake: f, root: root}
}

func (e loginEnv) do(t *testing.T, method, path, body string, header map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:5555"
	if body != "" || (method != http.MethodGet && method != http.MethodHead) {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead {
		req.Header.Set("Origin", "http://127.0.0.1:8080")
	}
	for k, v := range header {
		if v == "" {
			req.Header.Del(k)
			continue
		}
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func cookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %s cookie in %v", name, rec.Header().Values("Set-Cookie"))
	return nil
}

func (e loginEnv) login(t *testing.T) (*http.Cookie, *http.Cookie) {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/api/v1/auth/login", `{"account":"123456789012","userName":"bob","password":"correct horse 1"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %d %s", rec.Code, rec.Body)
	}
	return cookie(t, rec, SessionCookie), cookie(t, rec, CSRFCookie)
}

func TestLoginSetsHardenedCookies(t *testing.T) {
	e := newLoginEnv(t)
	rec := e.do(t, http.MethodPost, "/api/v1/auth/login", `{"account":"123456789012","userName":"bob","password":"correct horse 1"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %d %s", rec.Code, rec.Body)
	}
	var body struct {
		Principal string    `json:"principal"`
		Account   string    `json:"account"`
		ExpiresAt time.Time `json:"expiresAt"`
		CSRFToken string    `json:"csrfToken"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Principal != "arn:vws:iam::123456789012:user/bob" || body.Account != "123456789012" || body.CSRFToken == "" {
		t.Fatalf("login body %s %v", rec.Body, err)
	}
	if strings.Contains(rec.Body.String(), "correct horse") {
		t.Fatal("password echoed")
	}
	s := cookie(t, rec, SessionCookie)
	if !s.HttpOnly || !s.Secure || s.SameSite != http.SameSiteStrictMode || s.Path != "/" || s.MaxAge <= 0 {
		t.Errorf("session cookie not hardened: %+v", s)
	}
	if strings.Contains(rec.Body.String(), s.Value) {
		t.Error("session token in the body; it must only be in the HttpOnly cookie")
	}
	c := cookie(t, rec, CSRFCookie)
	if c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Value != body.CSRFToken {
		t.Errorf("csrf cookie: %+v", c)
	}
}

func TestLoginFailuresAreGeneric(t *testing.T) {
	e := newLoginEnv(t)
	var first string
	for _, body := range []string{
		`{"account":"123456789012","userName":"bob","password":"wrong"}`,
		`{"account":"123456789012","userName":"nobody","password":"correct horse 1"}`,
		`{"account":"210987654321","userName":"bob","password":"correct horse 1"}`,
	} {
		rec := e.do(t, http.MethodPost, "/api/v1/auth/login", body, nil)
		if rec.Code != http.StatusUnauthorized || len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s: %d %s", body, rec.Code, rec.Body)
		}
		if first == "" {
			first = rec.Body.String()
		} else if rec.Body.String() != first {
			t.Errorf("failure bodies differ: %s vs %s", first, rec.Body)
		}
	}
	for _, body := range []string{`{"userName":"bob"}`, `not json`, `{"account":"123456789012","userName":"bob","password":"x","extra":1}`} {
		if rec := e.do(t, http.MethodPost, "/api/v1/auth/login", body, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", body, rec.Code, rec.Body)
		}
	}
}

func TestSessionIsAuthorizedPerRequest(t *testing.T) {
	e := newLoginEnv(t)
	session, csrf := e.login(t)
	if rec := e.do(t, http.MethodGet, "/api/v1/vpcs", "", nil, session); rec.Code != http.StatusOK {
		t.Errorf("allowed list: %d %s", rec.Code, rec.Body)
	}
	rec := e.do(t, http.MethodGet, "/api/v1/auth/session", "", nil, session)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"principal":"arn:vws:iam::123456789012:user/bob"`) {
		t.Errorf("session: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(t, http.MethodGet, "/api/v1/buckets/b1", "", nil, session); rec.Code != http.StatusForbidden {
		t.Errorf("s3:ListBucket is not granted: %d %s", rec.Code, rec.Body)
	}
	mutate := map[string]string{"Idempotency-Key": "vpc-login-1", CSRFHeader: csrf.Value}
	if rec := e.do(t, http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.4.0.0/16"}`, mutate, session); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "PermissionDenied") {
		t.Errorf("denied mutation: %d %s", rec.Code, rec.Body)
	}
	vpcs := `{"Statement":[{"Effect":"Allow","Action":"ec2:CreateVpc","Resource":"*"}]}`
	if err := e.fake.PutInlinePolicy(t.Context(), e.account, iam.EntityUser, "bob", "vpcs", vpcs, ""); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.4.0.0/16"}`, mutate, session); rec.Code != http.StatusAccepted {
		t.Errorf("allowed mutation after the policy changed: %d %s", rec.Code, rec.Body)
	}
	noCSRF := map[string]string{"Idempotency-Key": "vpc-login-2"}
	if rec := e.do(t, http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.5.0.0/16"}`, noCSRF, session); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "csrf") {
		t.Errorf("mutation without the CSRF header: %d %s", rec.Code, rec.Body)
	}
	wrongCSRF := map[string]string{"Idempotency-Key": "vpc-login-3", CSRFHeader: "forged"}
	if rec := e.do(t, http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.6.0.0/16"}`, wrongCSRF, session, csrf); rec.Code != http.StatusForbidden {
		t.Errorf("mutation with a forged CSRF header: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(t, http.MethodPost, "/api/v1/auth/logout", "", map[string]string{CSRFHeader: csrf.Value}, session); rec.Code != http.StatusNoContent {
		t.Fatalf("logout %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(t, http.MethodGet, "/api/v1/vpcs", "", nil, session); rec.Code != http.StatusUnauthorized {
		t.Errorf("session after logout: %d %s", rec.Code, rec.Body)
	}
}

func TestUnauthenticatedConsoleIsRejected(t *testing.T) {
	e := newLoginEnv(t)
	for _, c := range []*http.Cookie{nil, {Name: SessionCookie, Value: "forged"}} {
		var cs []*http.Cookie
		if c != nil {
			cs = append(cs, c)
		}
		if rec := e.do(t, http.MethodGet, "/api/v1/vpcs", "", nil, cs...); rec.Code != http.StatusUnauthorized {
			t.Errorf("cookie %v: %d %s", c, rec.Code, rec.Body)
		}
	}
	// The bearer console token stays the account root until it is retired.
	if rec := e.do(t, http.MethodGet, "/api/v1/vpcs", "", map[string]string{"Authorization": "Bearer tok"}); rec.Code != http.StatusOK {
		t.Errorf("bearer root: %d %s", rec.Code, rec.Body)
	}
}

func TestRootLogin(t *testing.T) {
	e := newLoginEnv(t)
	if err := e.root.SetPassword(t.Context(), "root password 9"); err != nil {
		t.Fatal(err)
	}
	rec := e.do(t, http.MethodPost, "/api/v1/auth/login", `{"account":"123456789012","userName":"root","password":"root password 9"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("root login %d %s", rec.Code, rec.Body)
	}
	csrf := cookie(t, rec, CSRFCookie)
	mutate := map[string]string{"Idempotency-Key": "vpc-root-1", CSRFHeader: csrf.Value}
	if got := e.do(t, http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.7.0.0/16"}`, mutate, cookie(t, rec, SessionCookie)); got.Code != http.StatusAccepted {
		t.Errorf("root mutation: %d %s", got.Code, got.Body)
	}
}

// Every console route names the IAM action it is authorized as, so a new
// route cannot ship unauthorized.
func TestEveryRouteIsAuthorized(t *testing.T) {
	for _, pattern := range Routes() {
		if _, ok := routeAction(pattern); !ok {
			t.Errorf("route %s has no IAM action", pattern)
		}
	}
	if len(Routes()) < 40 {
		t.Errorf("only %d routes listed", len(Routes()))
	}
}

func TestLoginIsRateLimitedPerIP(t *testing.T) {
	e := newLoginEnv(t)
	bad := `{"account":"123456789012","userName":"bob","password":"wrong pass 1"}`
	for i := range LoginBurst {
		// Different users, so the per-user lockout is not what stops it.
		body := strings.Replace(bad, `"bob"`, `"user`+strconv.Itoa(i)+`"`, 1)
		if rec := e.do(t, http.MethodPost, "/api/v1/auth/login", body, nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	rec := e.do(t, http.MethodPost, "/api/v1/auth/login", bad, nil)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("over the burst: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	// Another address is not limited.
	other := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8080/api/v1/auth/login", strings.NewReader(`{"account":"123456789012","userName":"bob","password":"correct horse 1"}`))
	other.RemoteAddr = "192.0.2.99:1"
	other.Header.Set("Content-Type", "application/json")
	other.Header.Set("Origin", "http://127.0.0.1:8080")
	orec := httptest.NewRecorder()
	e.h.ServeHTTP(orec, other)
	if orec.Code != http.StatusOK {
		t.Errorf("other IP: %d %s", orec.Code, orec.Body)
	}
	// Tokens refill over time.
	*e.clock = e.clock.Add(LoginRefill)
	if rec := e.do(t, http.MethodPost, "/api/v1/auth/login", `{"account":"123456789012","userName":"bob","password":"correct horse 1"}`, nil); rec.Code != http.StatusOK {
		t.Errorf("after refill: %d %s", rec.Code, rec.Body)
	}
}

func TestBusyHashingIs503WithRetryAfter(t *testing.T) {
	e := newLoginEnv(t)
	release := e.fake.OccupyHashing()
	defer release()
	rec := e.do(t, http.MethodPost, "/api/v1/auth/login", `{"account":"123456789012","userName":"bob","password":"correct horse 1"}`, nil)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("busy: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
}

func TestStateChangingSessionRequestsNeedOriginAndJSON(t *testing.T) {
	e := newLoginEnv(t)
	login := `{"account":"123456789012","userName":"bob","password":"correct horse 1"}`
	for name, h := range map[string]map[string]string{
		"no origin":        {"Origin": ""},
		"foreign origin":   {"Origin": "https://evil.example"},
		"form content":     {"Content-Type": "application/x-www-form-urlencoded"},
		"text content":     {"Content-Type": "text/plain"},
		"no content type":  {"Content-Type": ""},
		"origin null":      {"Origin": "null"},
		"origin with path": {"Origin": "http://127.0.0.1:8080.evil.example"},
	} {
		rec := e.do(t, http.MethodPost, "/api/v1/auth/login", login, h)
		want := http.StatusForbidden
		if strings.Contains(name, "content") {
			want = http.StatusUnsupportedMediaType
		}
		if rec.Code != want {
			t.Errorf("login %s: %d %s", name, rec.Code, rec.Body)
		}
	}
	session, csrf := e.login(t)
	write := map[string]string{"Idempotency-Key": "vpc-origin-1", CSRFHeader: csrf.Value}
	vpcs := `{"Statement":[{"Effect":"Allow","Action":"ec2:CreateVpc","Resource":"*"}]}`
	if err := e.fake.PutInlinePolicy(t.Context(), e.account, iam.EntityUser, "bob", "vpcs", vpcs, ""); err != nil {
		t.Fatal(err)
	}
	for name, extra := range map[string]map[string]string{
		"foreign origin": {"Origin": "https://evil.example"},
		"no origin":      {"Origin": ""},
		"form content":   {"Content-Type": "application/x-www-form-urlencoded"},
	} {
		h := map[string]string{}
		for k, v := range write {
			h[k] = v
		}
		for k, v := range extra {
			h[k] = v
		}
		if rec := e.do(t, http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.4.0.0/16"}`, h, session); rec.Code < 400 {
			t.Errorf("session write with %s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := e.do(t, http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.4.0.0/16"}`, write, session); rec.Code != http.StatusAccepted {
		t.Errorf("same-origin JSON write: %d %s", rec.Code, rec.Body)
	}
	// The bearer token (no cookie) is not a browser session: no Origin needed.
	if rec := e.do(t, http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.8.0.0/16"}`, map[string]string{"Authorization": "Bearer tok", "Origin": "", "Idempotency-Key": "vpc-bearer-1"}); rec.Code != http.StatusAccepted {
		t.Errorf("bearer write: %d %s", rec.Code, rec.Body)
	}
}

func TestConfiguredOriginIsAllowed(t *testing.T) {
	e := newLoginEnv(t)
	e.h = New(Config{Service: cloudFor(t), IAM: iam.WithRoot(e.root, e.fake), Origins: []string{"https://console.vws.example"}})
	rec := e.do(t, http.MethodPost, "/api/v1/auth/login", `{"account":"123456789012","userName":"bob","password":"correct horse 1"}`, map[string]string{"Origin": "https://console.vws.example"})
	if rec.Code != http.StatusOK {
		t.Errorf("configured origin: %d %s", rec.Code, rec.Body)
	}
}

func cloudFor(t *testing.T) *cloud.Service {
	t.Helper()
	return cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()})
}
