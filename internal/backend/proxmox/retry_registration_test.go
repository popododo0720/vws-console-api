package proxmox

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
)

// TestRegistrationAfterAFailedFirstPushMakesTheDaemonReady repeats vws-console-api#1077: the first
// registration fails its self-check because a managed pool is missing; once the pool exists, the next
// registration succeeds and the daemon must become ready without a restart or a removal.
func TestRegistrationAfterAFailedFirstPushMakesTheDaemonReady(t *testing.T) {
	dir := privateDir(t)
	binary := filepath.Join(dir, "vws-region")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/vws-region")
	build.Dir = "../../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	tlsConfig := daemonCertificates(t, dir)
	s := scenario()
	s.Pools = []string{"123456789012"}
	s.Roles[0].Privs = append(s.Roles[0].Privs, "Pool.Audit")
	fake, err := pvefake.New(s)
	if err != nil {
		t.Fatal(err)
	}
	var missing atomic.Bool
	missing.Store(true)
	pve := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if missing.Load() && r.URL.Path == "/api2/json/pools/123456789012" {
			r.URL.Path = "/api2/json/pools/absent"
		}
		fake.ServeHTTP(w, r)
	}))
	pve.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: tlsConfig.Certificates}
	pve.StartTLS()
	defer pve.Close()
	writeFixture(t, filepath.Join(dir, "region.yaml"), []byte("read_only: true\npools:\n  project: '123456789012'\n"))
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	addr, ops := unusedAddress(t), unusedAddress(t)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary,
		"-config", filepath.Join(dir, "region.yaml"), "-region", "pve-test-1", "-state-dir", filepath.Join(dir, "state"),
		"-tls-cert-file", filepath.Join(dir, "cert.pem"), "-tls-key-file", filepath.Join(dir, "key.pem"),
		"-tls-ca-file", filepath.Join(dir, "ca.pem"), "-region-addr", addr, "-ops-addr", ops)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	cmd.Env = append(os.Environ(), "OTEL_EXPORTER_OTLP_ENDPOINT=")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("daemon log:\n%s", output.String())
		}
	}()
	awaitStatus(t, "http://"+ops+"/readyz", http.StatusServiceUnavailable)
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	put := func(generation int) (int, string) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, "https://"+addr+"/internal/v1/registration",
			strings.NewReader(`{"region":"pve-test-1","generation":`+strconv.Itoa(generation)+
				`,"cluster_name":"test","pveApiUrls":["`+pve.URL+`"],"caPem":`+strconv.Quote(string(caPEM))+
				`,"tokenId":"vws@pve!inventory","token":"fake-secret","zones":[{"letter":"a","nodes":["pve1"]}]}`))
		if err != nil {
			t.Fatal(err)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res.StatusCode, string(body)
	}
	if code, body := put(1); code == http.StatusOK || !strings.Contains(body, "does not exist") {
		t.Fatalf("first registration with the pool missing: %d %s", code, body)
	}
	missing.Store(false)
	if code, body := put(3); code != http.StatusOK {
		t.Fatalf("registration after the pool was created: %d %s", code, body)
	}
	// The registration is acknowledged only once the daemon serves it: the console reports success to the
	// operator, who runs region test and health at once.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+addr+"/internal/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status right after an acknowledged registration: %d %s", res.StatusCode, body)
	}
}
