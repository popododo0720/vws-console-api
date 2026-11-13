package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-lib/obs"

	"github.com/popododo0720/vws-console-api/internal/audit"
	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

type authorizationTransport struct {
	t     *testing.T
	calls int
}

func (a *authorizationTransport) Call(_ context.Context, service, method string, scope, _, dst any) error {
	a.t.Helper()
	a.calls++
	s, ok := scope.(backend.Scope)
	if !ok || s.Account.String() != "123456789012" || s.Principal != "arn:vws:iam::123456789012:user/reader" {
		a.t.Fatalf("caller scope: %+v", scope)
	}
	if service != "Compute" || method != "DescribeInstances" {
		a.t.Fatalf("unauthorized backend call: %s.%s", service, method)
	}
	*dst.(*resource.Page[resource.Instance]) = resource.Page[resource.Instance]{Items: []resource.Instance{}}
	return nil
}

func (a *authorizationTransport) OpenConsole(
	context.Context, backend.Scope, resource.InstanceID, resource.ConsoleKind,
) (resource.ConsoleSession, error) {
	a.t.Fatal("unauthorized console call")
	return resource.ConsoleSession{}, nil
}

func TestConsoleAndOperationDenialsBeforeRegion(t *testing.T) {
	account := mustParse[resource.AccountID](t, "123456789012")
	auth := iam.NewFake()
	if _, err := auth.CreateUser(t.Context(), account, "reader", "/"); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.CreateLoginProfile(t.Context(), account, "reader", "correct horse 1", false,
		backendtest.UserGrant(t.Context(), t, auth, account, "reader")); err != nil {
		t.Fatal(err)
	}
	principal := "arn:vws:iam::123456789012:user/reader"
	auth.AddStatement(principal, iam.Statement{
		Effect: iam.Allow, Actions: []string{"ec2:Describe*"}, Resources: []string{"*"},
	})
	login, err := auth.Login(t.Context(), iam.LoginRequest{
		Account: account, UserName: "reader", Password: "correct horse 1",
	})
	if err != nil {
		t.Fatal(err)
	}
	regions := backend.NewStaticRegions([]backend.ProxmoxRegion{{Name: "pve-test-1"}},
		[]backend.AWSAccount{{ID: "999999999999", AllowedRegions: []string{"us-east-1"}}})
	for _, region := range []string{"pve-test-1", "us-east-1"} {
		for _, action := range []string{"OpenConsole", "GetOperation"} {
			t.Run(region+"/"+action, func(t *testing.T) {
				for range 2 {
					var lines bytes.Buffer
					transport := &authorizationTransport{t: t}
					set, err := regionclient.New(transport)
					if err != nil {
						t.Fatal(err)
					}
					svc := cloud.New(cloud.Config{Backends: set, Regions: regions, Audit: audit.New(&lines)})
					h := console.New(console.Config{Service: svc, IAM: auth})
					path := "/api/v1/instances/i-0123456789abcdef0/console?kind=vnc"
					if action == "GetOperation" {
						path = "/api/v1/operations/op-compute-0123456789abcdef0123456789abcdef01234567"
					}
					req := httptest.NewRequestWithContext(obs.WithRequestID(t.Context(), "authorization-request"),
						http.MethodGet, "http://localhost"+path, nil)
					req.RemoteAddr = "192.0.2.7:1234"
					req.Header.Set("X-Vws-Region", region)
					req.Header.Set("Origin", "http://localhost")
					req.AddCookie(&http.Cookie{Name: console.SessionCookie, Value: login.Token})
					res := httptest.NewRecorder()
					h.ServeHTTP(res, req)
					if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), `"code":"PermissionDenied"`) ||
						transport.calls != 0 {
						t.Fatalf("denial before region: %d %s; calls=%d", res.Code, res.Body, transport.calls)
					}
					t.Run("audit", func(t *testing.T) {
						assertAuthorizationAudit(t, &lines, principal, region, "vws", action)
					})
				}
			})
		}
	}
}

func TestDescribeOnlyAuthorizationBothRegions(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account := mustParse[resource.AccountID](t, "123456789012")
	principal := "arn:vws:iam::123456789012:user/reader"
	auth := iam.NewFake()
	auth.AddKey(iam.Key{
		AccessKey: "READER", Secret: "reader-secret", Principal: iam.Principal{Account: account, ARN: principal},
	})
	auth.AddStatement(principal, iam.Statement{
		Effect: iam.Allow, Actions: []string{"ec2:Describe*"}, Resources: []string{"*"},
	})
	regions := backend.NewStaticRegions([]backend.ProxmoxRegion{{Name: "pve-test-1"}},
		[]backend.AWSAccount{{ID: "999999999999", AllowedRegions: []string{"us-east-1"}}})
	for _, region := range []string{"pve-test-1", "us-east-1"} {
		for _, surface := range []string{"console", "ec2"} {
			t.Run(region+"/"+surface, func(t *testing.T) {
				var lines bytes.Buffer
				transport := &authorizationTransport{t: t}
				set, err := regionclient.New(transport)
				if err != nil {
					t.Fatal(err)
				}
				svc := cloud.New(cloud.Config{Backends: set, Regions: regions, Audit: audit.New(&lines)})
				ui := console.New(console.Config{Service: svc, IAM: auth, Auth: console.BearerTokens{
					"reader": {Account: account, Principal: principal},
				}})
				query := ec2query.New(ec2query.Config{
					Service: svc, Authorizer: auth,
					Verifier: sigv4.NewVerifier(sigv4.Verifier{
						Service: sigv4.ServiceEC2, Regions: regions,
						Auth: iam.Authenticator(auth), Now: func() time.Time { return now },
					}),
				})
				for _, tc := range []struct {
					action, method, path string
				}{
					{"DescribeInstances", http.MethodGet, "/api/v1/instances"},
					{"RunInstances", http.MethodPost, "/api/v1/instances"},
					{"StopInstances", http.MethodPost, "/api/v1/instances/stop"},
					{"TerminateInstances", http.MethodPost, "/api/v1/instances/terminate"},
				} {
					t.Run(tc.action, func(t *testing.T) {
						lines.Reset()
						before := transport.calls
						ctx := obs.WithRequestID(t.Context(), "authorization-request")
						var req *http.Request
						h, deniedCode := ui, `"code":"PermissionDenied"`
						if surface == "console" {
							req = httptest.NewRequestWithContext(ctx, tc.method, "http://localhost"+tc.path,
								strings.NewReader(`{"userData":"must-not-be-audited"}`))
							req.Header.Set("Authorization", "Bearer reader")
							req.Header.Set("Content-Type", "application/json")
							req.Header.Set("X-Vws-Region", region)
						} else {
							form := url.Values{"Action": {tc.action}, "Version": {ec2query.Version}}
							req = httptest.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/", strings.NewReader(form.Encode()))
							req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
							if err := sigv4.Sign(req, sigv4.Credential{AccessKey: "READER", Secret: "reader-secret", Account: account},
								sigv4.ServiceEC2, region, now); err != nil {
								t.Fatal(err)
							}
							h, deniedCode = query, "<Code>UnauthorizedOperation</Code>"
						}
						req.RemoteAddr = "192.0.2.7:1234"
						res := httptest.NewRecorder()
						h.ServeHTTP(res, req)
						if tc.action == "DescribeInstances" {
							if res.Code != http.StatusOK || transport.calls != before+1 || lines.Len() != 0 {
								t.Fatalf("describe: %d %s; calls=%d audit=%s", res.Code, res.Body, transport.calls-before, &lines)
							}
							return
						}
						if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), deniedCode) ||
							transport.calls != before {
							t.Fatalf("denial: %d %s; calls=%d", res.Code, res.Body, transport.calls-before)
						}
						t.Run("audit", func(t *testing.T) {
							assertAuthorizationAudit(t, &lines, principal, region, "ec2", tc.action)
						})
					})
				}
			})
		}
	}
}

func assertAuthorizationAudit(t *testing.T, lines *bytes.Buffer, principal, region, service, action string) {
	t.Helper()
	if bytes.Count(lines.Bytes(), []byte("\n")) != 1 {
		t.Fatalf("want exactly one denial audit line, got %q", lines.String())
	}
	var entry map[string]any
	if err := json.Unmarshal(lines.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	destination := "pve"
	if region == "us-east-1" {
		destination = "aws"
	}
	for key, want := range map[string]string{
		"request_id": "authorization-request", "principal_arn": principal, "account": "123456789012",
		"region": region, "service": service, "action": action, "result": "denied",
		"destination": destination, "source_ip": "192.0.2.7", "operation_id": "",
	} {
		if entry[key] != want {
			t.Errorf("%s=%v, want %s", key, entry[key], want)
		}
	}
	if len(entry) != 14 || strings.Contains(lines.String(), "must-not-be-audited") {
		t.Fatalf("audit schema or request material: %s", lines)
	}
}
