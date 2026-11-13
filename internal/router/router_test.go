package router

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

type unreadBody struct{ t *testing.T }

func (b unreadBody) Read([]byte) (int, error) {
	b.t.Error("router read the body")
	return 0, errors.New("body must remain unread")
}
func (unreadBody) Close() error { return nil }

func scopeHeader(region, service string) string {
	return "AWS4-HMAC-SHA256 Credential=AKID/20261110/" + region + "/" + service +
		"/aws4_request, SignedHeaders=host, Signature=" + strings.Repeat("0", 64)
}

func TestCredentialScopeRoutingNeverReadsBody(t *testing.T) {
	catalog := backend.NewStaticRegions([]backend.ProxmoxRegion{{Name: "pve-test-1"}},
		[]backend.AWSAccount{{ID: "123456789012", AllowedRegions: []string{"ap-northeast-2"}}})
	for _, service := range []string{"ec2", "s3", "iam", "sts", "dynamodb", "lambda"} {
		for _, tc := range []struct{ region, want string }{
			{"pve-test-1", "local"},
			{"ap-northeast-2", "aws"},
			{"pve-unknown-1", "rejected"},
			{"xx-fake-1", "rejected"},
		} {
			t.Run(service+"/"+tc.region, func(t *testing.T) {
				want := tc.want
				switch {
				case service == "iam" || service == "sts":
					want = "local"
				case service != "ec2" && want == "aws":
					want = "forward"
				case service != "ec2" && service != "s3" && want == "local":
					want = "rejected"
				}
				got := ""
				handler := New(Config{
					Regions: catalog,
					Local:   http.HandlerFunc(func(http.ResponseWriter, *http.Request) { got = "local" }),
					AWS:     http.HandlerFunc(func(http.ResponseWriter, *http.Request) { got = "aws" }),
					Forward: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { got = "forward" }),
					Error: func(_ http.ResponseWriter, _ *http.Request, err error) {
						got = "rejected"
						rej, ok := sigv4.RejectionOf(err)
						if !ok || rej.Failure != sigv4.FailureMalformed ||
							resource.AsError(err).Message != "credential scope rejected" {
							t.Errorf("unexpected rejection: %v", err)
						}
					},
				})
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
				req.Body = unreadBody{t}
				req.Header.Set("Authorization", scopeHeader(tc.region, service))
				handler.ServeHTTP(httptest.NewRecorder(), req)
				if got != want {
					t.Fatalf("destination %q, want %q", got, want)
				}
			})
		}
	}
}

type failedCatalog struct{}

func (failedCatalog) ProxmoxRegions(context.Context) ([]backend.ProxmoxRegion, error) {
	return nil, errors.New("catalog unavailable")
}

func (failedCatalog) AWSAccounts(context.Context) ([]backend.AWSAccount, error) {
	return nil, errors.New("catalog unavailable")
}

func TestRoutingRegistrationRestartAndFailures(t *testing.T) {
	catalog := backend.NewStaticRegions(nil, nil)
	calls, rejected := 0, 0
	config := Config{
		Regions: catalog,
		Local:   http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }),
		AWS:     http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }),
		Error:   func(http.ResponseWriter, *http.Request, error) { rejected++ },
	}
	serve := func(h http.Handler, region string) {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
		req.Body = unreadBody{t}
		req.Header.Set("Authorization", scopeHeader(region, "ec2"))
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	h := New(config)
	serve(h, "pve-new-1")
	catalog.AddProxmoxRegion(backend.ProxmoxRegion{Name: "pve-new-1"})
	serve(h, "pve-new-1")
	serve(h, "pve-new-1")
	serve(New(config), "pve-new-1")
	if calls != 3 || rejected != 1 {
		t.Fatalf("registration/retry/restart: calls=%d rejected=%d", calls, rejected)
	}
	for _, region := range []string{
		"", "all", "../pve-new-1", "pve-new-1/extra", "pve-new-1\x00",
		"PVE-new-1", "pve-" + strings.Repeat("a", 64), "pve-unknown-1", "xx-fake-1",
	} {
		serve(h, region)
	}
	for _, region := range []string{"pve-new-1", "ap-northeast-2"} {
		config.Regions = failedCatalog{}
		serve(New(config), region)
	}
	if calls != 3 || rejected != 12 {
		t.Fatalf("failure reached a destination: calls=%d rejected=%d", calls, rejected)
	}
}
