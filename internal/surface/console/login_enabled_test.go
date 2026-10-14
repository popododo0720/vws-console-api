package console

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// newStaticEnv is the default install: -iam static, the bearer console
// token only, and console sign-in disabled even with a root password set.
func newStaticEnv(t *testing.T) loginEnv {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	root := iam.NewStatic("AKIDEXAMPLE", "secret", account)
	if err := root.SetPassword(t.Context(), "root password 9"); err != nil {
		t.Fatal(err)
	}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()})
	rootCaller := resource.Caller{Account: account, Subject: "console-token", Principal: iam.RootARN(account), Root: true}
	h := New(Config{Service: svc, IAM: root, Auth: BearerTokens{"tok": rootCaller}, LoginDisabled: true})
	return loginEnv{h: h, account: account, root: root}
}

func TestStaticSessionWithoutCredentialsSaysLoginDisabled(t *testing.T) {
	e := newStaticEnv(t)
	rec := e.do(t, http.MethodGet, "/api/v1/auth/session", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if got := rec.Body.String(); got != "{\"loginEnabled\":false}\n" {
		t.Errorf("body %q", got)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("cache-control %q", rec.Header().Get("Cache-Control"))
	}
	// A stale cookie from an earlier IAM install changes nothing.
	rec = e.do(t, http.MethodGet, "/api/v1/auth/session", "", nil, &http.Cookie{Name: SessionCookie, Value: "stale"})
	if rec.Code != http.StatusOK || rec.Body.String() != "{\"loginEnabled\":false}\n" {
		t.Errorf("stale cookie: %d %s", rec.Code, rec.Body)
	}
}

func TestStaticSessionWithBearerNamesRootAndLoginDisabled(t *testing.T) {
	e := newStaticEnv(t)
	rec := e.do(t, http.MethodGet, "/api/v1/auth/session", "", map[string]string{"Authorization": "Bearer tok"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["loginEnabled"] != false || got["principal"] != "arn:vws:iam::123456789012:root" || got["root"] != true || got["account"] != "123456789012" {
		t.Errorf("body %v", got)
	}
	rec = e.do(t, http.MethodGet, "/api/v1/auth/session", "", map[string]string{"Authorization": "Bearer wrong"})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("bad bearer: %d", rec.Code)
	}
}

func TestStaticBearerRoutesStillWork(t *testing.T) {
	e := newStaticEnv(t)
	if rec := e.do(t, http.MethodGet, "/api/v1/vpcs", "", map[string]string{"Authorization": "Bearer tok"}); rec.Code != http.StatusOK {
		t.Errorf("GET vpcs: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(t, http.MethodGet, "/api/v1/vpcs", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("GET vpcs without a token: %d", rec.Code)
	}
}

func TestStaticLoginAndLogoutAre501(t *testing.T) {
	e := newStaticEnv(t)
	body := `{"account":"123456789012","userName":"root","password":"root password 9"}`
	for _, tc := range []struct {
		name, path, body string
		hdr              map[string]string
		cookies          []*http.Cookie
	}{
		{"login with the root password", "/api/v1/auth/login", body, nil, nil},
		{"login from a foreign origin", "/api/v1/auth/login", body, map[string]string{"Origin": "https://evil.example"}, nil},
		{"logout", "/api/v1/auth/logout", "", nil, nil},
		{"logout with a cookie", "/api/v1/auth/logout", "", nil, []*http.Cookie{{Name: SessionCookie, Value: "x"}}},
		{"logout with bearer", "/api/v1/auth/logout", "", map[string]string{"Authorization": "Bearer tok"}, nil},
	} {
		rec := e.do(t, http.MethodPost, tc.path, tc.body, tc.hdr, tc.cookies...)
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s: status %d: %s", tc.name, rec.Code, rec.Body)
			continue
		}
		var got struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Error.Code != "Unimplemented" || got.Error.Message != "console sign-in requires -iam fake or grpc" {
			t.Errorf("%s: error %+v", tc.name, got.Error)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s: set cookies %v", tc.name, rec.Result().Cookies())
		}
	}
}

func TestIAMSessionSaysLoginEnabled(t *testing.T) {
	e := newLoginEnv(t)
	rec := e.do(t, http.MethodGet, "/api/v1/auth/session", "", map[string]string{"Authorization": "Bearer tok"})
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if got["loginEnabled"] != true {
		t.Errorf("bearer body %v", got)
	}
	login := e.do(t, http.MethodPost, "/api/v1/auth/login", `{"account":"123456789012","userName":"bob","password":"correct horse 1"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login %d %s", login.Code, login.Body)
	}
	if err := json.Unmarshal(login.Body.Bytes(), &got); err != nil || got["loginEnabled"] != true {
		t.Errorf("login body %v", got)
	}
	rec = e.do(t, http.MethodGet, "/api/v1/auth/session", "", nil, cookie(t, login, SessionCookie))
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK || got["loginEnabled"] != true {
		t.Errorf("cookie session %d %s", rec.Code, rec.Body)
	}
	// Signed out with sign-in enabled stays 401: the UI shows the sign-in page.
	if rec := e.do(t, http.MethodGet, "/api/v1/auth/session", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous session: %d", rec.Code)
	}
}
