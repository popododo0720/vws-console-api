package router_test

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/audit"
	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/router"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
	"github.com/popododo0720/vws-console-api/internal/surface/s3rest"
)

func TestAWSForwardingRequiresSignatureAndIAM(t *testing.T) {
	dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "r792-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "proxy.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var logs bytes.Buffer
	body := "Action=RebootInstances&Version=" + ec2query.Version + "&InstanceId.1=i-0123456789abcdef0"
	proxy := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(
		w http.ResponseWriter, r *http.Request,
	) {
		calls.Add(1)
		got, err := io.ReadAll(r.Body)
		if err != nil || string(got) != body && string(got) != "object bytes" ||
			r.Header.Get("Authorization") != "" || r.Header.Get("X-Amz-Security-Token") != "" ||
			r.Header.Get("X-Vws-Account") != "123456789012" ||
			r.Header.Get("X-Vws-Principal") != "arn:vws:iam::123456789012:root" ||
			r.Header.Get("X-Vws-Target-Region") != "ap-northeast-2" ||
			r.Header.Get("X-Vws-Evil") != "" {
			t.Errorf("incorrect forwarded body/identity: %q %v %v", got, r.Header, err)
		}
		w.WriteHeader(http.StatusAccepted)
	})}
	go func() { _ = proxy.Serve(listener) }()
	defer proxy.Close()
	f := router.NewForwarder(socket, audit.New(&logs))
	defer f.Close()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	auth := iam.NewStatic("AKIDEXAMPLE", "secret", account)
	catalog := backend.NewStaticRegions(nil, []backend.AWSAccount{
		{ID: "987654321098", AllowedRegions: []string{"ap-northeast-2"}},
	})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	for _, service := range []sigv4.Service{sigv4.ServiceEC2, sigv4.ServiceS3} {
		for _, mode := range []string{"valid", "bad signature", "denied"} {
			v := sigv4.NewVerifier(sigv4.Verifier{Service: service, Regions: catalog, Auth: iam.Authenticator(auth)})
			var authz iam.Authorizer = auth
			if mode == "denied" {
				authz = nil
			}
			svc := cloud.New(cloud.Config{Regions: catalog})
			handler := ec2query.New(ec2query.Config{
				Service: svc, Verifier: v, Authorizer: authz, Forward: f.Handler(service, ec2query.WriteError),
			})
			writeError := ec2query.WriteError
			content, method, path := body, http.MethodPost, "/"
			var forward http.Handler
			if service == sigv4.ServiceS3 {
				handler = nil
				forward = f.Any(router.ForwardConfig{
					Verifier: func(sigv4.Service) *sigv4.Verifier { return v }, Authorizer: authz, Error: s3rest.WriteError,
				})
				content, method, path, writeError = "object bytes", http.MethodPut, "/bucket/key", s3rest.WriteError
			}
			h := router.New(router.Config{
				Regions: catalog, AWS: handler, Forward: forward, Error: writeError,
				Local: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("AWS request reached local backend") }),
			})
			req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(content))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Vws-Account", "000000000000")
			req.Header.Set("X-Vws-Evil", "injected")
			signing := cred
			if mode == "bad signature" {
				signing.Secret = "wrong"
			}
			if err := sigv4.Sign(req, signing, service, "ap-northeast-2", time.Now()); err != nil {
				t.Fatal(err)
			}
			before := calls.Load()
			res := httptest.NewRecorder()
			h.ServeHTTP(res, req)
			if mode == "valid" {
				if res.Code != http.StatusAccepted || calls.Load() != before+1 {
					t.Fatalf("%s: %d %s; calls=%d", service, res.Code, res.Body, calls.Load())
				}
			} else if res.Code < 400 || calls.Load() != before {
				t.Fatalf("%s %s reached proxy: %d %s", service, mode, res.Code, res.Body)
			}
		}
	}
	if strings.Count(logs.String(), `"result":"accepted"`) != 2 ||
		strings.Count(logs.String(), `"service":"s3","action":"PutObject","resource_ids":[],"result":"denied"`) != 1 {
		t.Fatalf("missing mutation audits: %s", logs.String())
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	v := sigv4.NewVerifier(sigv4.Verifier{Service: sigv4.ServiceEC2, Regions: catalog, Auth: iam.Authenticator(auth)})
	if err := sigv4.Sign(req, cred, sigv4.ServiceEC2, "ap-northeast-2", time.Now()); err != nil {
		t.Fatal(err)
	}
	handler := ec2query.New(ec2query.Config{
		Service: cloud.New(cloud.Config{Regions: catalog}), Verifier: v, Authorizer: auth,
		Forward: f.Handler(sigv4.ServiceEC2, ec2query.WriteError),
	})
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable || strings.Contains(res.Body.String(), socket) {
		t.Fatalf("proxy failure: %d %s", res.Code, res.Body)
	}
}
