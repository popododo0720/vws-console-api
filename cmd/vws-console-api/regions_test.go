package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/admin/store/etcdstore/etcdtest"
	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/proxmoxtest"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

func bootstrapRegion(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	dir := t.TempDir()
	registry := etcdtest.Start(t)
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	key, err := x509.MarshalPKCS8PrivateKey(srv.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{
		certPath:                  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}),
		keyPath:                   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}),
		filepath.Join(dir, "kek"): []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	data := fmt.Sprintf(`iam:
  etcd_endpoints: [%s]
  tls: {ca_file: %s}
credentials:
  kek_file: %s
  mtls: {ca_file: %s, cert_file: %s, key_file: %s}
default_project: default
`, registry.EtcdEndpoints[0], registry.TLS.CAFile, filepath.Join(dir, "kek"), certPath, certPath, keyPath)
	return writeFile(t, data)
}

func TestRegionsProcessInventoryAndRestart(t *testing.T) {
	app, previous := &syncBuffer{}, slog.Default()
	var responses strings.Builder
	slog.SetDefault(slog.New(slog.NewJSONHandler(app, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	b := proxmoxtest.New(t)
	ids, err := proxmox.NewIDs("test")
	if err != nil {
		t.Fatal(err)
	}
	pveID, _, err := ids.Instance(proxmox.VM{UUID: "5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10"})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := regionapi.New(regionapi.Config{
		Backend: b.Set(), Capabilities: b, Region: "pve-test-1",
		Version: regionapi.Version{ReleaseLine: "1.0", ClusterName: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pveCalls, awsCalls atomic.Int32
	region := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pveCalls.Add(1)
		handler.ServeHTTP(w, r)
	}))
	region.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert}
	region.StartTLS()
	defer region.Close()
	path := bootstrapRegion(t, region)
	xml, err := os.ReadFile("../../internal/backend/awssdk/testdata/instances.xml")
	if err != nil {
		t.Fatal(err)
	}
	socketDir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "p755-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	socket := filepath.Join(socketDir, "proxy.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(
		w http.ResponseWriter, r *http.Request,
	) {
		awsCalls.Add(1)
		if r.Header.Get("X-Vws-Account") != "123456789012" ||
			r.Header.Get("X-Vws-Principal") != "arn:vws:iam::123456789012:root" ||
			r.Header.Get("X-Vws-Target-Region") != "us-east-1" {
			t.Errorf("incorrect proxy routing headers: %v", r.Header)
		}
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(strings.ReplaceAll(string(xml), "<nextToken>upstream-second</nextToken>", "")))
	})}
	go func() { _ = proxy.Serve(listener) }()
	defer proxy.Close()
	registry, _, closeRegistry, err := openRegistry(t.Context(), path, "regions")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeRegistry() })
	if _, err := registry.Regions().Create(t.Context(), store.Region{
		Name: "pve-test-1", RegionEndpoint: region.URL,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.AWSAccounts().Create(t.Context(), store.AWSAccount{
		ID: "123456789012", AllowedRegions: []string{"us-east-1"},
	}); err != nil {
		t.Fatal(err)
	}
	for attempt := range 2 {
		p := fakeProcess{console: freeAddr(t), ec2: freeAddr(t), s3: freeAddr(t), iam: freeAddr(t), ops: freeAddr(t)}
		ctx, cancel := context.WithCancel(t.Context())
		errc, done := make(chan error, 1), make(chan struct{})
		go func() {
			errc <- run(ctx, append(p.args(), "-backend=regions", "-global-config="+path,
				"-console-token=dev-token", "-access-key=AKIDEXAMPLE", "-secret=secret",
				"-default-region=pve-test-1", "-aws-proxy-socket="+socket))
			close(done)
		}()
		if err := waitListening(ctx, []string{p.console, p.ops}, errc, done); err != nil {
			cancel()
			t.Fatal(err)
		}
		call := func(path, name string, want int) string {
			t.Helper()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+p.console+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer dev-token")
			if name != "" {
				req.Header.Set("X-Vws-Region", name)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != want {
				t.Fatalf("%s %q: %d %s %v", path, name, resp.StatusCode, body, err)
			}
			if path == "/api/v1/instances" && want == 200 {
				var page resource.Page[resource.Instance]
				if err := json.Unmarshal(body, &page); err != nil {
					t.Fatalf("wrong regional instance identities: %s; %v", body, err)
				}
				wantIDs := map[string]bool{pveID.String(): true}
				switch name {
				case "us-east-1":
					wantIDs = map[string]bool{"i-0123456789abcdef0": true}
				case "all":
					wantIDs["i-0123456789abcdef0"] = true
				}
				if len(page.Items) != len(wantIDs) {
					t.Fatalf("wrong regional instance count: %s", body)
				}
				for _, inst := range page.Items {
					if !wantIDs[inst.ID.String()] {
						t.Fatalf("unexpected regional instance: %s", body)
					}
					delete(wantIDs, inst.ID.String())
				}
			}
			responses.Write(body)
			return string(body)
		}
		body := call("/api/v1/regions", "", 200)
		if !strings.Contains(body, "pve-test-1") || !strings.Contains(body, "us-east-1") {
			t.Fatalf("missing registered regions: %s", body)
		}
		beforePVE, beforeAWS := pveCalls.Load(), awsCalls.Load()
		call("/api/v1/instances", "", 200)
		call("/api/v1/instances", "pve-test-1", 200)
		if pveCalls.Load() != beforePVE+4 || awsCalls.Load() != beforeAWS {
			t.Fatal("default or named PVE routing reached another region")
		}
		call("/api/v1/instances", "us-east-1", 200)
		call("/api/v1/instances", "all", 200)
		if pveCalls.Load() != beforePVE+6 || awsCalls.Load() != beforeAWS+2 {
			t.Fatal("AWS or all-region inventory did not route correctly")
		}
		call("/api/v1/instances", "pve-unknown-1", 400)
		call("/api/v1/instances", strings.Repeat("a", 64), 400)
		if pveCalls.Load() != beforePVE+6 || awsCalls.Load() != beforeAWS+2 {
			t.Fatal("invalid header reached inventory")
		}
		if strings.Contains(call("/api/v1/addresses", "all", 200), "partial") {
			t.Fatal("an empty AWS read became a partial failure")
		}
		if attempt == 1 {
			region.Close()
			proxy.Close()
			call("/api/v1/buckets/probe-bucket", "pve-test-1", 503)
			call("/api/v1/instances", "us-east-1", 503)
		}
		http.DefaultClient.CloseIdleConnections()
		cancel()
		select {
		case err := <-errc:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(smokeTimeout):
			t.Fatal("regions process did not stop")
		}
	}
	output := app.String() + responses.String()
	for _, secret := range []string{socket, region.URL, "http://proxy/", "fake-secret"} {
		if strings.Contains(output, secret) || !strings.Contains(app.String(), "region unavailable") {
			t.Fatalf("missing safe failure log or exposed transport detail: %s", output)
		}
	}
}

func TestRegionHeaderBoundariesAndUnavailable(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	catalog := backend.NewStaticRegions([]backend.ProxmoxRegion{{Name: "pve-test-1", Endpoint: "https://unused"}}, nil)
	var calls atomic.Int32
	set, closeBackends, err := registeredBackends(catalog, func(string) (*regionapi.Client, error) {
		calls.Add(1)
		return nil, context.DeadlineExceeded
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer closeBackends()
	auth := iam.NewStatic("key", "secret", account)
	h := console.New(console.Config{
		Service: cloud.New(cloud.Config{Backends: set, Regions: catalog}),
		Auth: console.BearerTokens{"token": {
			Account: account, Principal: iam.RootARN(account), Root: true, Region: "pve-test-1",
		}},
		IAM: regionSessionIAM{Client: auth, account: account}, Region: "pve-test-1",
	})
	request := func(values []string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/instances", nil)
		if values == nil {
			req.AddCookie(&http.Cookie{Name: console.SessionCookie, Value: "session"})
		} else {
			req.Header.Set("Authorization", "Bearer token")
		}
		req.Header["X-Vws-Region"] = values
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for _, value := range []string{
		"unknown", strings.Repeat("x", 64), "pve-test-1\x00", "pve-test-1\n", "pve-test-1\t", " PVE",
	} {
		rec := request([]string{value})
		if rec.Code != 400 || calls.Load() != 0 {
			t.Fatalf("malicious header %q: %d; transports %d", value, rec.Code, calls.Load())
		}
	}
	duplicateResponse := request([]string{"pve-test-1", "all"})
	if duplicateResponse.Code != 400 || calls.Load() != 0 {
		t.Fatal("repeated region headers reached inventory")
	}
	start := time.Now()
	for _, value := range []string{"pve-test-1", "all"} {
		rec := request([]string{value})
		if (value == "all" && (rec.Code != 200 || !strings.Contains(rec.Body.String(), "partial"))) ||
			(value != "all" && rec.Code != 503) {
			t.Fatalf("unreachable region %s: %d %s", value, rec.Code, rec.Body)
		}
	}
	if time.Since(start) >= 8*time.Second {
		t.Fatal("unreachable region exceeded fan-out deadline")
	}
	rec := request(nil)
	if rec.Code != 503 || calls.Load() != 3 {
		t.Fatalf("cookie session default did not reach its region: %d %s", rec.Code, rec.Body)
	}
}

type regionSessionIAM struct {
	iam.Client
	account resource.AccountID
}

func (a regionSessionIAM) ValidateSession(context.Context, string) (iam.Session, error) {
	return iam.Session{Principal: iam.Principal{Account: a.account, ARN: iam.RootARN(a.account), Root: true}}, nil
}

func TestRegisteredRegionTransportDeadline(t *testing.T) {
	release := make(chan struct{})
	region := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	region.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert}
	region.StartTLS()
	defer region.Close()
	defer close(release)
	connect, err := regionConnection(bootstrapRegion(t, region))
	if err != nil {
		t.Fatal(err)
	}
	catalog := backend.NewStaticRegions([]backend.ProxmoxRegion{{Name: "pve-test-1", Endpoint: region.URL}}, nil)
	set, closeBackends, err := registeredBackends(catalog, connect, "")
	if err != nil {
		t.Fatal(err)
	}
	defer closeBackends()
	start := time.Now()
	page, err := set.Compute.DescribeInstances(t.Context(), backend.Scope{Region: "all"}, resource.InstanceQuery{})
	if err != nil || len(page.Partial) != 1 || time.Since(start) >= 8*time.Second {
		t.Fatalf("stalled mTLS region: %+v %v after %s", page, err, time.Since(start))
	}
}

func TestProxmoxRequiresRegionConfig(t *testing.T) {
	err := run(t.Context(), []string{"-backend=proxmox", "-region-config=" + filepath.Join(t.TempDir(), "missing")})
	if err == nil || !strings.Contains(err.Error(), "region.yaml") {
		t.Fatalf("missing region.yaml: %v", err)
	}
}

func TestRegionsRefusesDefaultCredentials(t *testing.T) {
	err := run(t.Context(), []string{"-backend=regions"})
	if err == nil || !strings.Contains(err.Error(), "-backend=regions needs") {
		t.Fatalf("regions accepted public development credentials: %v", err)
	}
}
