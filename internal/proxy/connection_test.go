package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-lib/obs/report"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

const connectionBody = `{"awsAccountId":"123456789012","roleArn":"arn:aws:iam::123456789012:role/inventory",` +
	`"externalId":"external-canary"}`

func connectionRequest(ctx context.Context, body string) *http.Request {
	r := httptest.NewRequestWithContext(ctx, "POST", "/internal/v1/aws-accounts/test", strings.NewReader(body))
	for key, value := range map[string]string{
		"Content-Type": "application/json", "X-Vws-Account": "123456789012",
		"X-Vws-Principal": "principal", "X-Vws-Target-Service": "sts",
	} {
		r.Header.Set(key, value)
	}
	return r
}

func TestAWSConnectionStepsAndCacheIsolation(t *testing.T) {
	assume := `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>session-key</AccessKeyId>` +
		`<SecretAccessKey>session-secret</SecretAccessKey><SessionToken>session-token</SessionToken>` +
		`<Expiration>2036-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`
	identity := `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account>` +
		`</GetCallerIdentityResult></GetCallerIdentityResponse>`
	for _, tc := range []struct {
		name, external, action, body, message string
		status                                int
		assumed, matched                      bool
	}{
		{"success", "external-canary", "", "", "AWS account identity matched", 200, true, true},
		{"wrong_external", "wrong-canary", "", "", "AssumeRole was denied", 200, false, false},
		{
			"source", "external-canary", "AssumeRole", "<ErrorResponse><Error><Code>ExpiredToken</Code></Error></ErrorResponse>",
			"source credentials", 403, false, false,
		},
		{"other_rejection", "external-canary", "AssumeRole", "", "rejected the AssumeRole", 400, false, false},
		{"unavailable", "external-canary", "AssumeRole", "", "STS unavailable", 503, false, false},
		{"empty", "external-canary", "AssumeRole", "<AssumeRoleResponse/>", "unusable", 200, false, false},
		{"oversized", "external-canary", "AssumeRole", strings.Repeat("x", 65537), "unusable", 200, false, false},
		{
			"mismatch", "external-canary", "GetCallerIdentity",
			"<GetCallerIdentityResponse><GetCallerIdentityResult><Account>000000000000</Account>" +
				"</GetCallerIdentityResult></GetCallerIdentityResponse>",
			"another account", 200, true, false,
		},
		{"identity_rejected", "external-canary", "GetCallerIdentity", "", "session credentials", 403, true, false},
		{"identity_malformed", "external-canary", "GetCallerIdentity", "<broken", "unusable", 200, true, false},
		{
			"assume_wrong_root", "external-canary", "AssumeRole",
			strings.ReplaceAll(assume, "AssumeRoleResponse", "Unexpected"), "unusable", 200, false, false,
		},
		{"assume_trailing", "external-canary", "AssumeRole", assume + "<Unexpected/>", "unusable", 200, false, false},
		{
			"assume_two_results", "external-canary", "AssumeRole",
			strings.Replace(assume, "</AssumeRoleResponse>", "<AssumeRoleResult/></AssumeRoleResponse>", 1),
			"unusable", 200, false, false,
		},
		{"identity_trailing", "external-canary", "GetCallerIdentity", identity + "<x>", "unusable", 200, true, false},
		{
			"identity_duplicate", "external-canary", "GetCallerIdentity",
			strings.Replace(identity, "<Account>", "<Account>000000000000</Account><Account>", 1),
			"unusable", 200, true, false,
		},
		{
			"identity_missing", "external-canary", "GetCallerIdentity",
			strings.Replace(identity, "<Account>123456789012</Account>", "", 1), "unusable", 200, true, false,
		},
		{
			"identity_invalid", "external-canary", "GetCallerIdentity",
			strings.Replace(identity, "123456789012", "12345678901x", 1), "unusable", 200, true, false,
		},
		{"identity_status", "external-canary", "GetCallerIdentity", identity, "session credentials", 403, true, false},
		{
			"identity_oversized", "external-canary", "GetCallerIdentity",
			identity + strings.Repeat(" ", 65537), "unusable", 200, true, false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			var assumes, identities atomic.Int32
			sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.ParseForm()
				action := r.Form.Get("Action")
				credential := f.p.source
				if action == "AssumeRole" {
					assumes.Add(1)
					if r.Form.Get("DurationSeconds") != "3600" ||
						!strings.HasPrefix(r.Form.Get("RoleSessionName"), "vws-123456789012-") {
						t.Error("forwarding session parameters changed")
					}
					if r.Form.Get("ExternalId") != "external-canary" {
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprint(w, "<ErrorResponse><Error><Code>AccessDenied</Code>"+
							"<Message>external-canary</Message></Error></ErrorResponse>")
						return
					}
				} else {
					identities.Add(1)
					credential = sigv4.Credential{AccessKey: "session-key", Secret: "session-secret", SessionToken: "session-token"}
				}
				got := r.Header.Get("Authorization")
				r.Body = io.NopCloser(strings.NewReader(r.PostForm.Encode()))
				at, _ := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
				if err := sigv4.Sign(r, credential, sigv4.ServiceSTS, "us-east-1", at); err != nil ||
					got != r.Header.Get("Authorization") {
					t.Error("invalid STS signature")
				}
				switch action {
				case tc.action:
					w.WriteHeader(tc.status)
					fmt.Fprint(w, tc.body)
				case "AssumeRole":
					fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>session-key</AccessKeyId>`+
						`<SecretAccessKey>session-secret</SecretAccessKey><SessionToken>session-token</SessionToken>`+
						`<Expiration>%s</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`,
						time.Now().Add(time.Hour).Format(time.RFC3339))
				default:
					fmt.Fprint(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account>`+
						`</GetCallerIdentityResult></GetCallerIdentityResponse>`)
				}
			}))
			defer sts.Close()
			f.p.sts = sts.URL
			f.p.cache[[32]byte{1}] = sigv4.Credential{AccessKey: "sentinel"}
			before, _ := f.registry.AWSAccounts().Get(t.Context(), "123456789012")
			var logs bytes.Buffer
			old := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
			defer slog.SetDefault(old)
			for range 2 {
				w := httptest.NewRecorder()
				f.p.ServeHTTP(w, connectionRequest(t.Context(), strings.Replace(connectionBody, "external-canary", tc.external, 1)))
				var out struct {
					Steps []resource.ConnectionStep `json:"steps"`
				}
				if w.Header().Get("Cache-Control") != "no-store" ||
					json.Unmarshal(w.Body.Bytes(), &out) != nil || !resource.ValidAWSConnectionSteps(out.Steps) ||
					(out.Steps[0].Result == resource.ConnectionPass) != tc.assumed ||
					(out.Steps[1].Result == resource.ConnectionPass) != tc.matched ||
					!strings.Contains(w.Body.String(), tc.message) || strings.Contains(w.Body.String()+logs.String(), "canary") {
					t.Fatalf("unsafe or wrong steps: %d %s", w.Code, w.Body)
				}
			}
			after, _ := f.registry.AWSAccounts().Get(t.Context(), "123456789012")
			if !reflect.DeepEqual(before, after) || len(f.p.cache) != 1 || f.p.cache[[32]byte{1}].AccessKey != "sentinel" ||
				f.originCalls != 0 || assumes.Load() < 2 || (identities.Load() != 0) != tc.assumed {
				t.Fatal("test reused cache, wrote state, skipped fresh STS, or called origin")
			}
		})
	}
}

func TestAWSConnectionDenialIsNotReported(t *testing.T) {
	f := setup(t)
	var reports atomic.Int32
	var malformed atomic.Bool
	report.Configure(report.Sink{CountError: func(context.Context, string) { reports.Add(1) }})
	defer report.Configure(report.Sink{})
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if malformed.Load() {
			fmt.Fprint(w, "<broken")
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>")
	}))
	defer sts.Close()
	f.p.sts = sts.URL
	w := httptest.NewRecorder()
	f.p.ServeHTTP(w, connectionRequest(t.Context(), connectionBody))
	if reports.Load() != 0 || !strings.Contains(w.Body.String(), "AssumeRole was denied") {
		t.Fatalf("expected diagnostic denial reported: count=%d response=%s", reports.Load(), w.Body)
	}
	f.request("Action=DescribeInstances")
	if reports.Load() != 1 {
		t.Fatal("forwarding stopped reporting failures")
	}
	malformed.Store(true)
	f.p.ServeHTTP(httptest.NewRecorder(), connectionRequest(t.Context(), connectionBody))
	if reports.Load() != 2 {
		t.Fatal("diagnostic stopped reporting malformed STS responses")
	}
}

func TestAWSConnectionBoundaryAndCancellation(t *testing.T) {
	f := setup(t)
	for _, body := range []string{
		"null", "{}", connectionBody + "{}", strings.Replace(connectionBody, `"externalId"`, `"ExternalId"`, 1),
		strings.Replace(connectionBody, `"externalId"`, `"externalId":"ab","externalId"`, 1),
		strings.Replace(connectionBody, "external-canary", `bad\u0000value`, 1),
		strings.Replace(connectionBody, "external-canary", strings.Repeat("x", 1225), 1),
		strings.Repeat(" ", 16385) + connectionBody,
	} {
		w := httptest.NewRecorder()
		f.p.ServeHTTP(w, connectionRequest(t.Context(), body))
		if w.Code != 400 || f.stsCalls != 0 || f.originCalls != 0 {
			t.Fatalf("boundary accepted: %d", w.Code)
		}
	}
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Method = "GET" },
		func(r *http.Request) { r.URL.RawQuery = "externalId=canary" },
		func(r *http.Request) { r.Header.Add("X-Vws-Principal", "other") },
		func(r *http.Request) { r.Header.Set("X-Vws-Account", "000000000000") },
		func(r *http.Request) { r.Header.Set("X-Vws-Principal", strings.Repeat("x", 2049)) },
	} {
		r := connectionRequest(t.Context(), connectionBody)
		change(r)
		w := httptest.NewRecorder()
		f.p.ServeHTTP(w, r)
		if w.Code != 400 || f.stsCalls != 0 {
			t.Fatal("invalid metadata reached STS")
		}
	}
	entered := make(chan struct{})
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
	}))
	defer sts.Close()
	f.p.sts = sts.URL
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		f.p.ServeHTTP(w, connectionRequest(ctx, connectionBody))
		done <- w
	}()
	select {
	case <-entered:
	case w := <-done:
		t.Fatalf("request ended before STS: %d %s", w.Code, w.Body)
	case <-time.After(5 * time.Second):
		t.Fatal("request did not reach STS")
	}
	cancel()
	select {
	case w := <-done:
		if !strings.Contains(w.Body.String(), "STS unavailable") {
			t.Fatalf("cancellation: %s", w.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled request did not finish")
	}
}
