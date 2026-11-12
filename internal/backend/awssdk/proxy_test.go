package awssdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/proxy"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

type accounts struct{}

func (accounts) Account(context.Context, string) (proxy.Account, error) {
	return proxy.Account{
		RoleARN: "arn:aws:iam::123456789012:role/inventory", ExternalID: "fixture",
		Regions: []string{"us-east-1"},
	}, nil
}

func setup(t *testing.T, fixture string, status int) *Backend {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "environment-key-canary")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "environment-secret-canary")
	t.Setenv("AWS_SESSION_TOKEN", "environment-token-canary")
	t.Setenv("HTTP_PROXY", "http://untrusted.invalid:8888")
	t.Setenv("HTTPS_PROXY", "http://untrusted.invalid:8888")
	xml, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatal(err)
	}
	nextXML, err := os.ReadFile(filepath.Join("testdata", "instances-next.xml"))
	if err != nil {
		t.Fatal(err)
	}
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("ExternalId") != "fixture" || r.Form.Get("Action") != "AssumeRole" {
			t.Errorf("unexpected STS request: %v", r.Form)
		}
		fmt.Fprint(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials>`+
			`<AccessKeyId>fixture-session</AccessKeyId><SecretAccessKey>fixture-secret</SecretAccessKey>`+
			`<SessionToken>fixture-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration>`+
			`</Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	t.Cleanup(sts.Close)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("Action") != "DescribeInstances" ||
			r.Header.Get("X-Amz-Security-Token") != "fixture-token" || r.Header.Get("X-Vws-Account") != "" {
			t.Error("request did not pass through the signing proxy")
		}
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(status)
		switch r.Form.Get("NextToken") {
		case "":
			w.Write(xml)
		case "upstream-second":
			w.Write(nextXML)
		default:
			t.Errorf("unexpected upstream cursor: %v", r.Form)
		}
	}))
	t.Cleanup(origin.Close)
	p, err := proxy.New(accounts{}, sigv4.Credential{AccessKey: "fixture-source", Secret: "fixture-source-secret"},
		sts.URL, "us-east-1", origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	socket := fixtureSocket(t)
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Amz-Security-Token") != "" ||
			r.Header.Get("X-Vws-Account") != "123456789012" || r.Header.Get("X-Vws-Principal") != "principal" {
			t.Error("backend credentials or incorrect forwarding identity")
		}
		p.ServeHTTP(w, r)
	}), ReadHeaderTimeout: callTimeout}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Close()
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	})
	b, err := New(Config{
		Socket: socket, Account: "123456789012", Region: "us-east-1",
		Principal: func(context.Context) string { return "principal" },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func fixtureSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "aws")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return filepath.Join(dir, "proxy.sock")
}
