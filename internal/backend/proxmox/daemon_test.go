package proxmox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

func daemonCertificates(t *testing.T, dir string) *tls.Config {
	t.Helper()
	var config *tls.Config
	if !t.Run("certificates", func(t *testing.T) {
		cryptotest.SetGlobalRandom(t, 1)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ca := &x509.Certificate{
			SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		writeFixture(t, filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		ca, err = x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err = x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		writeFixture(t, filepath.Join(dir, "cert.pem"), certPEM)
		writeFixture(t, filepath.Join(dir, "key.pem"), keyPEM)
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		config = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}}
	}) {
		t.FailNow()
	}
	return config
}

func writeFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func unusedAddress(t *testing.T) string {
	t.Helper()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func awaitStatus(t *testing.T, url string, status int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	client := &http.Client{Timeout: time.Second}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == status {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s never returned %d", url, status)
		case <-ticker.C:
		}
	}
}

func TestRegionDaemonReadsRestartAndReadiness(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "vws-region")
	build := exec.CommandContext(t.Context(), "go", "build", "-race", "-o", binary, "./cmd/vws-region")
	build.Dir = "../../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	tlsConfig := daemonCertificates(t, dir)
	fake, err := pvefake.New(scenario())
	if err != nil {
		t.Fatal(err)
	}
	var unavailable atomic.Bool
	gate := make(chan struct{})
	pve := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-gate:
		case <-r.Context().Done():
			return
		}
		if unavailable.Load() {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fake.ServeHTTP(w, r)
	}))
	pve.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: tlsConfig.Certificates}
	pve.StartTLS()
	defer pve.Close()
	writeFixture(t, filepath.Join(dir, "region.yaml"), []byte("read_only: true\n"))
	reg := snapshot(t, dir)
	start := func() (*regionapi.Client, string, func()) {
		addr, ops := unusedAddress(t), unusedAddress(t)
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Minute)
		cmd := exec.CommandContext(ctx, binary,
			"-config", filepath.Join(dir, "region.yaml"), "-registration-file", reg,
			"-pve-endpoint", pve.URL, "-pve-ca-file", filepath.Join(dir, "ca.pem"),
			"-tls-cert-file", filepath.Join(dir, "cert.pem"), "-tls-key-file", filepath.Join(dir, "key.pem"),
			"-tls-ca-file", filepath.Join(dir, "ca.pem"), "-region-addr", addr, "-ops-addr", ops)
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		cmd.Env = append(os.Environ(), "OTEL_EXPORTER_OTLP_ENDPOINT=")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			defer cancel()
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Error(err)
			}
			if err := cmd.Wait(); err != nil {
				t.Errorf("daemon: %v\n%s", err, output.String())
			}
		}
		t.Cleanup(stop)
		client, err := regionapi.NewClient("https://"+addr, tlsConfig)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.Close)
		return client, "http://" + ops, stop
	}
	first, ops, stop := start()
	awaitStatus(t, ops+"/readyz", http.StatusServiceUnavailable)
	close(gate)
	awaitStatus(t, ops+"/readyz", http.StatusOK)
	awaitStatus(t, ops+"/healthz", http.StatusOK)
	awaitStatus(t, ops+"/metrics", http.StatusOK)
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	read := func(c *regionapi.Client) resource.Page[resource.Instance] {
		var page resource.Page[resource.Instance]
		if err := c.Call(t.Context(), "Compute", "DescribeInstances",
			backend.Scope{Account: account}, resource.InstanceQuery{}, &page); err != nil {
			t.Fatal(err)
		}
		return page
	}
	want := read(first)
	second, secondOps, _ := start()
	awaitStatus(t, secondOps+"/readyz", http.StatusOK)
	if got := read(second); !reflect.DeepEqual(got, want) {
		t.Fatalf("two daemons disagree: got=%+v want=%+v", got, want)
	}
	caps, err := second.Capabilities(t.Context())
	if err != nil || caps.Region != "pve-test-1" {
		t.Fatalf("capabilities=%+v err=%v", caps, err)
	}
	unavailable.Store(true)
	awaitStatus(t, ops+"/readyz", http.StatusServiceUnavailable)
	unavailable.Store(false)
	awaitStatus(t, ops+"/readyz", http.StatusOK)
	stop()
	restarted, restartOps, _ := start()
	awaitStatus(t, restartOps+"/readyz", http.StatusOK)
	if got := read(restarted); !reflect.DeepEqual(got, want) {
		t.Fatalf("restart changed inventory: got=%+v want=%+v", got, want)
	}
	for _, method := range fake.RequestMethods() {
		if !strings.EqualFold(method, http.MethodGet) {
			t.Fatalf("PVE mutation: %s", method)
		}
	}
}
