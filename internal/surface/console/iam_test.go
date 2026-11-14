package console

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

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/iamquery"
)

func iamEnv(t *testing.T) loginEnv {
	t.Helper()
	e := newLoginEnv(t)
	h := e.h.(*handler)
	e.h = New(Config{Service: h.svc, IAM: h.iam, Admin: e.fake, Auth: h.auth, Now: h.now})
	return e
}

func iamAllow(t *testing.T, e loginEnv, action string) {
	t.Helper()
	doc := `{"Statement":[{"Effect":"Allow","Action":"` + action + `","Resource":"*"}]}`
	if err := e.fake.PutInlinePolicy(t.Context(), e.account, iam.EntityUser, "bob", "iam", doc,
		backendtest.EntityGrant(t.Context(), t, e.fake, e.account, iam.EntityUser, "bob")); err != nil {
		t.Fatal(err)
	}
}

func iamStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status %d, want %d: %s", rec.Code, want, rec.Body)
	}
}

func TestIAMRoutesRequireSession(t *testing.T) {
	e := newLoginEnv(t)
	for _, route := range []string{
		"GET /api/v1/iam/users", "POST /api/v1/iam/users",
		"GET /api/v1/iam/users/bob", "DELETE /api/v1/iam/users/bob",
		"POST /api/v1/iam/users/bob/login-profile", "PATCH /api/v1/iam/users/bob/login-profile",
		"DELETE /api/v1/iam/users/bob/login-profile",
	} {
		method, path, _ := strings.Cut(route, " ")
		iamStatus(t, e.do(t, method, path, "", nil), http.StatusUnauthorized)
	}
}

func TestIAMRoutesRequirePermission(t *testing.T) {
	e := iamEnv(t)
	session, csrf := e.login(t)
	for pattern := range iamRoutes() {
		method, path, _ := strings.Cut(pattern, " ")
		path = strings.NewReplacer("{name}", "bob", "{user}", "bob").Replace(path)
		t.Run(pattern, func(t *testing.T) {
			rec := e.do(t, method, path, "", map[string]string{CSRFHeader: csrf.Value}, session)
			iamStatus(t, rec, http.StatusForbidden)
			if !strings.Contains(rec.Body.String(), `"code":"AccessDenied"`) {
				t.Fatalf("wrong error envelope: %s", rec.Body)
			}
		})
	}
}

func TestIAMListUsersPermissionDoesNotGrantCreate(t *testing.T) {
	e := iamEnv(t)
	iamAllow(t, e, "iam:ListUsers")
	session, csrf := e.login(t)
	iamStatus(t, e.do(t, "GET", "/api/v1/iam/users", "", nil, session), http.StatusOK)
	rec := e.do(t, "POST", "/api/v1/iam/users", `{"userName":"carol"}`,
		map[string]string{CSRFHeader: csrf.Value, "Idempotency-Key": "create"}, session)
	iamStatus(t, rec, http.StatusForbidden)
	if !strings.Contains(rec.Body.String(), `"code":"AccessDenied"`) {
		t.Fatal(rec.Body)
	}
}

func TestIAMWritesRequireCSRFAndOrigin(t *testing.T) {
	for _, tc := range []struct{ group, method, path, body string }{
		{"users", "POST", "/api/v1/iam/users", `{"userName":"carol"}`},
		{"loginProfile", "PATCH", "/api/v1/iam/users/bob/login-profile", `{"password":"replacement secret 9"}`},
	} {
		t.Run(tc.group, func(t *testing.T) {
			e := iamEnv(t)
			iamAllow(t, e, "iam:*")
			session, csrf := e.login(t)
			for _, headers := range []map[string]string{
				{"Idempotency-Key": "create"},
				{"Idempotency-Key": "create", CSRFHeader: csrf.Value, "Origin": "https://evil.example"},
			} {
				iamStatus(t, e.do(t, tc.method, tc.path, tc.body, headers, session), http.StatusForbidden)
			}
			users, err := e.fake.ListUsers(t.Context(), e.account, "/")
			if err != nil || len(users) != 1 || users[0].Name != "bob" {
				t.Fatalf("users changed: %v %v", users, err)
			}
			iamStatus(t, e.do(t, "POST", "/api/v1/auth/login",
				`{"account":"123456789012","userName":"bob","password":"correct horse 1"}`, nil), http.StatusOK)
		})
	}
}

func TestIAMUserLifecycleAndReplay(t *testing.T) {
	e := iamEnv(t)
	iamAllow(t, e, "iam:*")
	session, csrf := e.login(t)
	headers := map[string]string{CSRFHeader: csrf.Value, "Idempotency-Key": "first-user"}
	first := e.do(t, "POST", "/api/v1/iam/users", `{"userName":"carol","path":"/team/"}`, headers, session)
	iamStatus(t, first, http.StatusOK)
	replay := e.do(t, "POST", "/api/v1/iam/users", `{"path":"/team/","userName":"carol"}`, headers, session)
	iamStatus(t, replay, http.StatusOK)
	if first.Body.String() != replay.Body.String() {
		t.Fatalf("replay differs: %s / %s", first.Body, replay.Body)
	}
	mismatch := e.do(t, "POST", "/api/v1/iam/users", `{"userName":"other"}`, headers, session)
	iamStatus(t, mismatch, http.StatusConflict)
	if !strings.Contains(mismatch.Body.String(), `"code":"IdempotencyMismatch"`) {
		t.Fatal(mismatch.Body)
	}
	iamStatus(t, e.do(t, "GET", "/api/v1/iam/users/other", "", nil, session), http.StatusNotFound)
	rec := e.do(t, "GET", "/api/v1/iam/users/carol", "", nil, session)
	iamStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"userName":"carol"`) ||
		!strings.Contains(rec.Body.String(), `"arn":"arn:aws:iam::123456789012:user/team/carol"`) {
		t.Fatal(rec.Body)
	}
	iamStatus(t, e.do(t, "DELETE", "/api/v1/iam/users/carol", "", headers, session), http.StatusOK)
}

func TestIAMMalformedInputNeverCreatesUser(t *testing.T) {
	for _, body := range []string{
		`{"userName":"bad/name"}`, `{"userName":"carol","userName":"dave"}`,
		`{"userName":"carol","path":"` + strings.Repeat("x", 1<<20) + `"}`,
	} {
		e := iamEnv(t)
		backend := &iamCreateCounter{Directory: e.fake}
		e.h.(*handler).iamRunner = iamquery.NewRunner(iamquery.Config{
			Admin: backend, Authorizer: iam.WithRoot(e.root, e.fake),
		})
		rec := e.do(t, "POST", "/api/v1/iam/users", body,
			map[string]string{"Authorization": "Bearer tok", "Idempotency-Key": "bad"})
		iamStatus(t, rec, http.StatusBadRequest)
		if backend.calls != 0 {
			t.Fatalf("malformed input reached CreateUser %d times", backend.calls)
		}
	}
}

type iamCreateCounter struct {
	iam.Directory
	calls int
}

func (s *iamCreateCounter) CreateUser(ctx context.Context, a resource.AccountID, name, path string) (iam.User, error) {
	s.calls++
	return s.Directory.CreateUser(ctx, a, name, path)
}

func TestIAMLoginProfileLifecycleLogsNoPassword(t *testing.T) {
	e := iamEnv(t)
	var logs bytes.Buffer
	h := e.h.(*handler)
	h.log = slog.New(slog.NewJSONHandler(&logs, nil))
	e.h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(obs.WithRequestID(r.Context(), "iam-request-569")))
	})
	headers := map[string]string{"Authorization": "Bearer tok", "Idempotency-Key": "profile-user"}
	iamStatus(t, e.do(t, "POST", "/api/v1/iam/users", `{"userName":"carol"}`, headers), http.StatusOK)
	headers["Idempotency-Key"] = "profile"
	const password = "password-canary-569-1"
	rec := e.do(t, "POST", "/api/v1/iam/users/carol/login-profile",
		`{"password":"`+password+`","passwordResetRequired":true}`, headers)
	iamStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"passwordResetRequired":true`) {
		t.Fatal(rec.Body)
	}
	iamStatus(t, e.do(t, "PATCH", "/api/v1/iam/users/carol/login-profile",
		`{"password":"updated-canary-569-2","passwordResetRequired":false}`, headers), http.StatusOK)
	iamStatus(t, e.do(t, "DELETE", "/api/v1/iam/users/carol/login-profile", "", headers), http.StatusOK)
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 4 || strings.Contains(logs.String(), password) || strings.Contains(logs.String(), "updated-canary") {
		t.Fatalf("unsafe or missing logs: %s", &logs)
	}
	for _, line := range lines {
		var event map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &event); err != nil ||
			event["action"] == nil || string(event["outcome"]) != "200" ||
			string(event["request_id"]) != `"iam-request-569"` {
			t.Fatalf("incomplete event: %s %v", line, err)
		}
	}
}
