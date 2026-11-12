package console

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/awssdk"
	"github.com/popododo0720/vws-console-api/internal/proxy"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/throttle"
)

func TestAdminAWSConnectionRestartAndRetry(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 923)
	e, registry, app, audit := accountFixture(t)
	accountCall(t, e, "POST", validAccount(), "", 201)
	before, _ := registry.AWSAccounts().Get(t.Context(), accountID)
	var assumes, identities, origins atomic.Int32
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		switch r.Form.Get("Action") {
		case "AssumeRole":
			assumes.Add(1)
			if r.Form.Get("ExternalId") != validAccount()["externalId"] {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, validAccount()["externalId"])
				return
			}
			fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials>`+
				`<AccessKeyId>session-key</AccessKeyId><SecretAccessKey>session-secret</SecretAccessKey>`+
				`<SessionToken>session-token</SessionToken><Expiration>%s</Expiration>`+
				`</Credentials></AssumeRoleResult></AssumeRoleResponse>`, time.Now().Add(time.Hour).Format(time.RFC3339))
		case "GetCallerIdentity":
			identities.Add(1)
			fmt.Fprintf(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>%s</Account>`+
				`</GetCallerIdentityResult></GetCallerIdentityResponse>`, accountID)
		default:
			t.Error("unexpected STS action")
		}
	}))
	defer sts.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { origins.Add(1) }))
	defer origin.Close()
	dir, err := os.MkdirTemp("", "a")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	for range 2 {
		p, err := proxy.New(proxy.RegistryAccounts{Registry: registry},
			sigv4.Credential{AccessKey: "source-key", Secret: "source-secret"}, sts.URL, "us-east-1", origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		socket := filepath.Join(dir, "s")
		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: p, ReadHeaderTimeout: time.Second}
		done := make(chan error, 1)
		go func() { done <- server.Serve(listener) }()
		client, err := awssdk.NewConnectionClient(socket)
		if err != nil {
			t.Fatal(err)
		}
		h := e.h.(*handler)
		e.h = New(Config{
			Registry: registry, AdminKey: h.adminKey, Audit: h.audit, Logger: h.log,
			Auth: h.auth, IAM: h.iam, AccountConnection: client.TestConnection,
		})
		for _, path := range []string{accountPath + "/test", accountPath + "/" + accountID + "/test"} {
			body := "{}"
			if path == accountPath+"/test" {
				b, _ := json.Marshal(validAccount())
				body = string(b)
			}
			beforeCalls := assumes.Load()
			bad := e.do(t, "POST", path, body, map[string]string{
				"Authorization": "Bearer tok", "Content-Type": "text/plain",
			})
			if bad.Code != http.StatusUnsupportedMediaType || assumes.Load() != beforeCalls {
				t.Fatalf("non-JSON request reached STS: status=%d calls=%d", bad.Code, assumes.Load()-beforeCalls)
			}
			for range 2 {
				rec := e.do(t, "POST", path, body, map[string]string{"Authorization": "Bearer tok"})
				if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" ||
					strings.Count(rec.Body.String(), `"PASS"`) != 2 {
					t.Fatalf("connection: %d %s", rec.Code, rec.Body)
				}
				if strings.Contains(rec.Body.String()+app.String()+audit.String(), validAccount()["externalId"].(string)) {
					t.Fatal("ExternalId escaped")
				}
			}
		}
		client.Close()
		server.Close()
		<-done
		steps := client.TestConnection(t.Context(), resource.AWSConnectionRequest{
			AccountID: accountID, RoleARN: before.RoleARN, ExternalID: validAccount()["externalId"].(string),
		}, "principal")
		if len(steps) != 2 || steps[0].Message != "AWS forwarding proxy unavailable" {
			t.Fatalf("stopped proxy: %+v", steps)
		}
	}
	after, _ := registry.AWSAccounts().Get(t.Context(), accountID)
	if !reflect.DeepEqual(before, after) || assumes.Load() != 8 || identities.Load() != 8 || origins.Load() != 0 {
		t.Fatalf("state or calls changed: assume=%d identity=%d origin=%d", assumes.Load(), identities.Load(), origins.Load())
	}
}

func TestAdminAWSConnectionSharesWriteLimit(t *testing.T) {
	e, _, _, _ := accountFixture(t)
	h := e.h.(*handler)
	calls := 0
	h.accountConnection = func(context.Context, resource.AWSConnectionRequest, string) []resource.ConnectionStep {
		calls++
		return resource.AWSConnectionSteps(true, true)
	}
	limits := throttle.DefaultLimits()
	limits.Mutate.Burst = 1
	h.requests = throttle.New(limits, func() time.Time { return *e.clock })
	b, _ := json.Marshal(validAccount())
	for _, want := range []int{200, 429} {
		rec := e.do(t, "POST", accountPath+"/test", string(b), map[string]string{"Authorization": "Bearer tok"})
		if rec.Code != want {
			t.Fatalf("write limiter: %d", rec.Code)
		}
	}
	if calls != 1 {
		t.Fatalf("proxy called %d times", calls)
	}
}

func TestAdminAWSConnectionRejectsMaliciousInput(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 923)
	e, registry, app, audit := accountFixture(t)
	accountCall(t, e, "POST", validAccount(), "", 201)
	calls := 0
	h := e.h.(*handler)
	h.accountConnection = func(context.Context, resource.AWSConnectionRequest, string) []resource.ConnectionStep {
		calls++
		return resource.AWSConnectionSteps(true, true)
	}
	head := map[string]string{"Authorization": "Bearer tok"}
	for _, field := range []string{"awsAccountId", "roleArn", "externalId", "allowedRegions"} {
		in := validAccount()
		delete(in, field)
		body, _ := json.Marshal(in)
		rec := e.do(t, "POST", accountPath+"/test", string(body), head)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), `"field":"body"`) || calls != 0 {
			t.Fatalf("missing %s: %d %s", field, rec.Code, rec.Body)
		}
	}
	for _, path := range []string{accountPath + "/test", accountPath + "/" + accountID + "/test"} {
		for _, body := range []string{
			`null`, `[]`, `{} {}`, `{"externalId":null}`, `{"ExternalId":"canary"}`,
			`{"secret-canary":1,"secret-canary":2}`, strings.Repeat(" ", 1<<20) + "{}",
		} {
			rec := e.do(t, "POST", path, body, head)
			want := 400
			if path == accountPath+"/test" && len(body) > 1<<20 {
				want = 413
			}
			if rec.Code != want || strings.Contains(rec.Body.String()+app.String()+audit.String(), "secret-canary") {
				t.Fatalf("malicious input: %d %s", rec.Code, rec.Body)
			}
		}
	}
	for key, value := range map[string]any{
		"awsAccountId": "12345678901", "roleArn": "arn:aws:iam::000000000000:role/Admin",
		"externalId": strings.Repeat("x", 1225), "allowedRegions": []string{"us-east-1", "us-east-1"},
	} {
		in := validAccount()
		in[key] = value
		b, _ := json.Marshal(in)
		if rec := e.do(t, "POST", accountPath+"/test", string(b), head); rec.Code != 400 {
			t.Fatalf("invalid %s: %d", key, rec.Code)
		}
	}
	if calls != 0 {
		t.Fatal("invalid input reached proxy")
	}
	stored, _ := registry.AWSAccounts().Get(t.Context(), accountID)
	validRole := stored.RoleARN
	stored.RoleARN = "invalid"
	registry.AWSAccounts().Update(t.Context(), stored)
	rec := e.do(t, "POST", accountPath+"/"+accountID+"/test", "{}", head)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "save it again") || calls != 0 {
		t.Fatal("invalid saved registration reached proxy")
	}
	stored, _ = registry.AWSAccounts().Get(t.Context(), accountID)
	stored.RoleARN = validRole
	stored.SealedExternalID.Ciphertext[0] ^= 1
	registry.AWSAccounts().Update(t.Context(), stored)
	rec = e.do(t, "POST", accountPath+"/"+accountID+"/test", "{}", head)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "save it again") || calls != 0 {
		t.Fatal("corrupt saved credential reached proxy")
	}
}
