package console

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-lib/obs"

	"github.com/popododo0720/vws-console-api/internal/admin/secret"
	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/audit"
	"github.com/popododo0720/vws-console-api/internal/throttle"
)

const (
	accountPath = "/api/v1/admin/aws-accounts"
	accountID   = "222222222222"
)

func accountFixture(t *testing.T) (loginEnv, *store.Registry, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	e, g := adminFixture(t)
	key, err := secret.New("global", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var app, auditLog bytes.Buffer
	h := e.h.(*handler)
	h.adminKey, h.audit = key, audit.New(&auditLog)
	h.log = slog.New(slog.NewJSONHandler(&app, nil))
	return e, g, &app, &auditLog
}

func validAccount() map[string]any {
	return map[string]any{
		"awsAccountId": accountID, "roleArn": "arn:aws:iam::" + accountID + ":role/team/Admin",
		"externalId":     "distinctive-canary-external-761",
		"allowedRegions": []string{"us-east-1", "us-gov-west-1", "cn-north-1", "ap-southeast-4"},
	}
}

func accountCall(t *testing.T, e loginEnv, method string, body any, match string, want int) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	path := accountPath
	if method != http.MethodPost && method != http.MethodGet {
		path += "/" + accountID
	}
	rec := e.do(t, method, path, string(b), map[string]string{"Authorization": "Bearer tok", "If-Match": match})
	if rec.Code != want || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s: %d %s", method, rec.Code, rec.Body)
	}
	return rec
}

func TestAdminAccountValidation(t *testing.T) {
	for _, tc := range []struct {
		field string
		value any
	}{
		{"awsAccountId", ""},
		{"awsAccountId", "12345678901"},
		{"awsAccountId", "12345678901x"},
		{"awsAccountId", "1234567890123"},
		{"roleArn", ""},
		{"roleArn", "arn:aws:iam::000000000000:role/Admin"},
		{"roleArn", "arn:aws:iam::" + accountID + ":user/Admin"},
		{"roleArn", "arn:vws:iam::" + accountID + ":role/Admin"},
		{"roleArn", "arn:aws:iam::" + accountID + ":role/" + strings.Repeat("a", 65)},
		{"roleArn", "arn:aws:iam::" + accountID + ":role/team/a b"},
		{"roleArn", "arn:aws:iam::" + accountID + ":role//Admin"},
		{"roleArn", "arn:aws:iam::" + accountID + ":role/" + strings.Repeat("a", 512) + "/Admin"},
		{"roleArn", strings.Repeat("a", 2049)},
		{"externalId", nil},
		{"externalId", ""},
		{"externalId", "x"},
		{"externalId", strings.Repeat("a", 1225)},
		{"externalId", "bad secret"},
		{"externalId", "bad\u2603"},
		{"allowedRegions", nil},
		{"allowedRegions", []string{}},
		{"allowedRegions", []string{"us-east-1", "us-east-1"}},
		{"allowedRegions", []string{"pve-seoul-1"}},
		{"allowedRegions", []string{"not-a-region"}},
		{"allowedRegions", []string{"US-east-1"}},
		{"allowedRegions", []string{"us-east-0"}},
		{"unknown", "secret-canary"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			e, _, _, _ := accountFixture(t)
			body := validAccount()
			body[tc.field] = tc.value
			rec := accountCall(t, e, "POST", body, "", 400)
			field := tc.field
			if field == "unknown" {
				field = "body"
			}
			if !strings.Contains(rec.Body.String(), `"field":"`+field+`"`) {
				t.Fatalf("missing field %s: %s", field, rec.Body)
			}
		})
	}
	for _, external := range []string{"ab", strings.Repeat("a", 1224), "a_+=,.@:/-"} {
		e, _, _, _ := accountFixture(t)
		body := validAccount()
		body["externalId"] = external
		accountCall(t, e, "POST", body, "", 201)
	}
	e, _, _, _ := accountFixture(t)
	accountCall(t, e, "PATCH", nil, "", 400)
	for body, want := range map[string]int{`{`: 400, `{} {}`: 400, strings.Repeat(" ", 1<<20) + "{}": 413} {
		rec := e.do(t, "POST", accountPath, body, map[string]string{"Authorization": "Bearer tok"})
		if rec.Code != want {
			t.Fatalf("malformed or oversized body: %d", rec.Code)
		}
	}
}

func TestAdminAccountLifecycleAndCanary(t *testing.T) {
	e, g, app, auditLog := accountFixture(t)
	post := accountCall(t, e, "POST", validAccount(), "", 201)
	stored, err := g.AWSAccounts().Get(t.Context(), accountID)
	if err != nil || !stored.ExternalID.Set || len(stored.SealedExternalID.Ciphertext) == 0 {
		t.Fatalf("stored secret: %v", err)
	}
	plain, err := e.h.(*handler).adminKey.Open(stored.SealedExternalID, accountID)
	if err != nil || string(plain) != validAccount()["externalId"] {
		t.Fatal("stored credential did not decrypt")
	}
	responses := []string{post.Body.String()}
	accountCall(t, e, "POST", validAccount(), "", 409)
	accountCall(t, e, "PATCH", map[string]any{}, "", 400)
	accountCall(t, e, "PATCH", map[string]any{}, `"0"`, 409)
	accountCall(t, e, "PATCH", map[string]any{"awsAccountId": "333333333333"}, post.Header().Get("ETag"), 400)
	patch := accountCall(t, e, "PATCH", map[string]any{"allowedRegions": []string{"eu-west-1"}},
		post.Header().Get("ETag"), 200)
	updated, err := g.AWSAccounts().Get(t.Context(), accountID)
	if err != nil || !reflect.DeepEqual(stored.SealedExternalID, updated.SealedExternalID) ||
		updated.RoleARN != stored.RoleARN || updated.Version == stored.Version {
		t.Fatalf("omitted fields or version changed incorrectly: %v", err)
	}
	responses = append(responses, patch.Body.String())
	h := e.h.(*handler)
	e.h = New(Config{Registry: g, AdminKey: h.adminKey, Audit: h.audit, Logger: h.log, Auth: h.auth, IAM: h.iam})
	for _, path := range []string{accountPath, accountPath + "/" + accountID} {
		rec := e.do(t, "GET", path, "", map[string]string{"Authorization": "Bearer tok"})
		if rec.Code != 200 {
			t.Fatalf("read after restart: %d", rec.Code)
		}
		responses = append(responses, rec.Body.String())
	}
	accountCall(t, e, "DELETE", nil, post.Header().Get("ETag"), 409)
	accountCall(t, e, "DELETE", nil, patch.Header().Get("ETag"), 204)
	accountCall(t, e, "DELETE", nil, "", 404)
	accountCall(t, e, "POST", validAccount(), "", 201)
	accountCall(t, e, "DELETE", nil, "", 204)
	output := strings.Join(responses, "\n") + app.String() + auditLog.String()
	for _, forbidden := range []string{
		validAccount()["externalId"].(string), base64.StdEncoding.EncodeToString(stored.SealedExternalID.Ciphertext),
		"sealedExternalId", "ciphertext",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatal("secret or ciphertext escaped its store")
		}
	}
	lines := strings.Split(strings.TrimSpace(auditLog.String()), "\n")
	actions := []string{
		"Register", "Register", "Update", "Update", "Update", "Update", "Remove", "Remove", "Remove", "Register", "Remove",
	}
	if len(lines) != len(actions) {
		t.Fatalf("audit lines %d, want %d", len(lines), len(actions))
	}
	for i, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if entry["action"] != "Admin"+actions[i]+"AwsAccount" || entry["destination"] != "admin" ||
			entry["principal_arn"] == "" || entry["account"] != e.account.String() ||
			entry["source_ip"] != "192.0.2.10" || entry["result"] == "" || len(entry) != 14 {
			t.Fatalf("audit schema: %s", line)
		}
	}
	req := httptest.NewRequestWithContext(obs.WithRequestID(t.Context(), "account-request-761"),
		"DELETE", accountPath+"/"+accountID, nil)
	req.Header.Set("Authorization", "Bearer tok")
	e.h.ServeHTTP(httptest.NewRecorder(), req)
	if !strings.Contains(auditLog.String(), `"request_id":"account-request-761"`) ||
		!strings.Contains(auditLog.String(), `"resource_ids":["`+accountID+`"]`) {
		t.Fatal("audit lost request or resource id")
	}
}

type failedAccountStore struct {
	store.Backend
	err error
}

func (b failedAccountStore) Create(context.Context, string, []byte) (store.Version, error) {
	return 0, b.err
}

func TestAdminAccountStoreErrors(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
	}{
		{store.ErrExists, 409},
		{store.ErrConflict, 409},
		{store.ErrNotFound, 404},
		{errors.New("backend unavailable"), 503},
	} {
		e, _, _, auditLog := accountFixture(t)
		e.h.(*handler).registry = store.New(failedAccountStore{Backend: store.NewMemory(), err: tc.err})
		accountCall(t, e, "POST", validAccount(), "", tc.status)
		if strings.Count(auditLog.String(), "\n") != 1 {
			t.Fatal("failed write did not audit exactly once")
		}
	}
}

func TestAdminAccountWritesRequireRootKeyAndCSRF(t *testing.T) {
	for _, method := range []string{"POST", "PATCH", "DELETE"} {
		e, _, _, auditLog := accountFixture(t)
		user, _ := e.login(t)
		path := accountPath
		if method != "POST" {
			path += "/" + accountID
		}
		rec := e.do(t, method, path, "{}", map[string]string{CSRFHeader: csrfToken(user.Value)}, user)
		if rec.Code != 403 || strings.Count(auditLog.String(), "\n") != 1 {
			t.Fatalf("non-root %s: %d %s", method, rec.Code, rec.Body)
		}
		e.h.(*handler).adminKey = nil
		accountCall(t, e, method, validAccount(), `"1"`, 503)
		if rec := e.do(t, "GET", accountPath, "", map[string]string{"Authorization": "Bearer tok"}); rec.Code != 200 {
			t.Fatal("missing KEK blocked reads")
		}
	}
	e, _, _, _ := accountFixture(t)
	if err := e.root.SetPassword(t.Context(), "root password 9"); err != nil {
		t.Fatal(err)
	}
	login := e.do(t, "POST", "/api/v1/auth/login",
		`{"account":"123456789012","userName":"root","password":"root password 9"}`, nil)
	root := cookie(t, login, SessionCookie)
	if rec := e.do(t, "POST", accountPath, "{}", nil, root); rec.Code != 403 {
		t.Fatal("cookie write bypassed CSRF")
	}
	limits := throttle.DefaultLimits()
	limits.Mutate.Burst = 1
	e.h.(*handler).requests = throttle.New(limits, func() time.Time { return *e.clock })
	accountCall(t, e, "POST", validAccount(), "", 201)
	accountCall(t, e, "DELETE", nil, "", 429)
}
