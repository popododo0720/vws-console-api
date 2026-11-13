package console

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/throttle"
)

func adminFixture(t *testing.T) (loginEnv, *store.Registry) {
	t.Helper()
	e := newLoginEnv(t)
	g := store.New(store.NewMemory())
	if _, err := g.Regions().Create(t.Context(), store.Region{
		Name: "pve-lab-1", ClusterName: "lab", TokenSecret: store.DescribeSecret("pve-test-secret"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.AWSAccounts().Create(t.Context(), store.AWSAccount{
		ID: "123456789012", ExternalID: store.DescribeSecret("external-test-secret"),
	}); err != nil {
		t.Fatal(err)
	}
	e.h.(*handler).registry = g
	return e, g
}

func TestAdminRoutesRequireRoot(t *testing.T) {
	e, _ := adminFixture(t)
	// An IAM grant cannot bypass the phase-1 fixed rule.
	if err := e.fake.PutInlinePolicy(t.Context(), e.account, iam.EntityUser, "bob", "admin",
		`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
		backendtest.EntityGrant(t.Context(), t, e.fake, e.account, iam.EntityUser, "bob")); err != nil {
		t.Fatal(err)
	}
	user, _ := e.login(t)
	if err := e.root.SetPassword(t.Context(), "root password 9"); err != nil {
		t.Fatal(err)
	}
	login := e.do(t, "POST", "/api/v1/auth/login",
		`{"account":"123456789012","userName":"root","password":"root password 9"}`, nil)
	root := cookie(t, login, SessionCookie)
	for _, path := range []string{
		"regions", "regions/pve-lab-1", "aws-accounts", "aws-accounts/123456789012",
		"permissions", "projects", "projects/123456789012",
	} {
		for _, who := range []struct {
			name   string
			cookie *http.Cookie
			status int
		}{
			{"anonymous", nil, 401}, {"user", user, 403}, {"root", root, 200},
		} {
			t.Run(path+"/"+who.name, func(t *testing.T) {
				var cookies []*http.Cookie
				if who.cookie != nil {
					cookies = append(cookies, who.cookie)
				}
				rec := e.do(t, "GET", "/api/v1/admin/"+path, "", nil, cookies...)
				if rec.Code != who.status {
					t.Fatalf("status %d: %s", rec.Code, rec.Body)
				}
				for _, secret := range []string{"pve-test-secret", "external-test-secret"} {
					if strings.Contains(rec.Body.String(), secret) {
						t.Fatal("secret in response")
					}
				}
				if who.status == 200 && path != "permissions" && path != "projects" && rec.Header().Get("ETag") == "" {
					t.Fatal("missing ETag")
				}
				if path == "permissions" {
					if who.status == 401 {
						return
					}
					var body permissionsBody
					if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
						t.Fatal(err)
					}
					if body.Permissions == nil || (who.status == 403 && len(body.Permissions) != 0) ||
						(who.status == 200 && len(body.Permissions) != 10) {
						t.Fatalf("permissions: %s", rec.Body)
					}
				}
			})
		}
	}
}

func TestAdminETagTracksUpdatesAndRestart(t *testing.T) {
	e, g := adminFixture(t)
	head := map[string]string{"Authorization": "Bearer tok"}
	for _, collection := range []string{"regions", "aws-accounts"} {
		id := "pve-lab-1"
		if collection == "aws-accounts" {
			id = "123456789012"
		}
		path := "/api/v1/admin/" + collection
		before := e.do(t, "GET", path, "", head)
		var version store.Version
		if collection == "regions" {
			v, err := g.Regions().Get(t.Context(), id)
			if err != nil {
				t.Fatal(err)
			}
			v, err = g.Regions().Update(t.Context(), v)
			if err != nil {
				t.Fatal(err)
			}
			version = v.Version
		} else {
			v, err := g.AWSAccounts().Get(t.Context(), id)
			if err != nil {
				t.Fatal(err)
			}
			v, err = g.AWSAccounts().Update(t.Context(), v)
			if err != nil {
				t.Fatal(err)
			}
			version = v.Version
		}
		e.h = New(Config{Registry: g, Auth: e.h.(*handler).auth, IAM: iam.WithRoot(e.root, e.fake)})
		after := e.do(t, "GET", path, "", head)
		if before.Header().Get("ETag") == after.Header().Get("ETag") {
			t.Fatal("stale collection ETag")
		}
		detail := e.do(t, "GET", path+"/"+id, "", head)
		if detail.Header().Get("ETag") != strconv.Quote(strconv.FormatInt(int64(version), 10)) {
			t.Fatal("wrong version ETag")
		}
		again := e.do(t, "GET", path+"/"+id, "", head)
		if detail.Body.String() != again.Body.String() || detail.Header().Get("ETag") != again.Header().Get("ETag") {
			t.Fatal("repeated read changed state")
		}
	}
}

func TestAdminRejectsMalformedAndUnavailable(t *testing.T) {
	e, _ := adminFixture(t)
	head := map[string]string{"Authorization": "Bearer tok"}
	for path, want := range map[string]int{
		"regions/bad": 400, "regions/pve-lab-2": 404, "aws-accounts/bad": 400,
		"aws-accounts/000000000000": 404, "regions/pve-lab-1%2Fextra": 400,
		"unknown": 404, "regions?ignored=1": 400, "permissions?ignored=1": 400,
	} {
		if rec := e.do(t, "GET", "/api/v1/admin/"+path, "", head); rec.Code != want {
			t.Errorf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
	if rec := e.do(t, "POST", "/api/v1/admin/regions", "{}", head); rec.Code != 503 ||
		!strings.Contains(rec.Body.String(), "credentials.kek_file") {
		t.Fatalf("write without KEK: %d %s", rec.Code, rec.Body)
	}
	e.h.(*handler).registry = nil
	if rec := e.do(t, "GET", "/api/v1/admin/regions", "", head); rec.Code != 503 {
		t.Fatal("unavailable registry returned success")
	}
}

func TestAdminListSkipsUndecodableRecords(t *testing.T) {
	for _, tc := range []struct {
		collection string
		valid      string
		bad        string
		value      string
	}{
		{"regions", "pve-lab-1", "pve-bad-1", `{"name":"pve-lab-1"}`},
		{"aws-accounts", "123456789012", "000000000000", `{"awsAccountId":"123456789012"}`},
	} {
		t.Run(tc.collection, func(t *testing.T) {
			e, _ := adminFixture(t)
			b := store.NewMemory()
			for name, value := range map[string]string{tc.valid: tc.value, tc.bad: `not json`} {
				if _, err := b.Create(t.Context(), tc.collection+"/"+name, []byte(value)); err != nil {
					t.Fatal(err)
				}
			}
			var logs bytes.Buffer
			e.h.(*handler).registry = store.New(b)
			e.h.(*handler).log = slog.New(slog.NewJSONHandler(&logs, nil))
			rec := e.do(t, "GET", "/api/v1/admin/"+tc.collection, "", map[string]string{"Authorization": "Bearer tok"})
			if rec.Code != http.StatusOK {
				t.Fatalf("list with a corrupt record: %d %s", rec.Code, rec.Body)
			}
			var body struct {
				Items []json.RawMessage `json:"items"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body.Items) != 1 || !strings.Contains(string(body.Items[0]), tc.valid) ||
				strings.Contains(rec.Body.String(), tc.bad) || rec.Header().Get("ETag") == "" {
				t.Fatalf("list did not retain only the valid record: %s", rec.Body)
			}
			if !strings.Contains(logs.String(), `"count":1`) ||
				strings.Contains(logs.String(), tc.valid) || strings.Contains(logs.String(), tc.bad) {
				t.Fatalf("skipped records must be reported without identifiers: %s", logs.String())
			}
		})
	}
}

func TestAdminSecretMetadata(t *testing.T) {
	e, _ := adminFixture(t)
	for path, field := range map[string]string{
		"regions/pve-lab-1": "tokenSecret", "aws-accounts/123456789012": "externalId",
	} {
		rec := e.do(t, "GET", "/api/v1/admin/"+path, "", map[string]string{"Authorization": "Bearer tok"})
		var body map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		var metadata store.SecretMetadata
		if err := json.Unmarshal(body[field], &metadata); err != nil {
			t.Fatal(err)
		}
		if !metadata.Set || len(metadata.Fingerprint) != 8 {
			t.Fatalf("bad metadata: %s", rec.Body)
		}
	}
}

func TestAdminRoutesAreRateLimited(t *testing.T) {
	for _, path := range []string{
		"regions", "regions/pve-lab-1", "aws-accounts", "aws-accounts/123456789012", "permissions",
	} {
		t.Run(path, func(t *testing.T) {
			e, _ := adminFixture(t)
			now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
			limits := throttle.DefaultLimits()
			limits.Describe.Burst = 1
			limits.Mutate.Burst = 1
			e.h.(*handler).requests = throttle.New(limits, func() time.Time { return now })
			head := map[string]string{"Authorization": "Bearer tok"}
			if rec := e.do(t, "GET", "/api/v1/admin/"+path, "", head); rec.Code != http.StatusOK {
				t.Fatalf("first admin read: %d %s", rec.Code, rec.Body)
			}
			rec := e.do(t, "GET", "/api/v1/admin/"+path, "", head)
			if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" ||
				!strings.Contains(rec.Body.String(), `"code":"ResourceExhausted","message":"Request limit exceeded."`) {
				t.Fatalf("admin read past the burst: %d %q %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body)
			}
		})
	}
}
