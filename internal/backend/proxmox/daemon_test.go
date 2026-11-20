package proxmox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
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
			Subject:      pkix.Name{CommonName: "region test CA"},
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
			Subject:      pkix.Name{CommonName: "region test leaf"},
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
	awaitClientStatus(t, &http.Client{Timeout: time.Second}, url, status)
}

func awaitClientStatus(t *testing.T, client *http.Client, url string, status int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
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

// TestRegionDaemonKeepsStateAcrossRestart runs the real daemon with only a
// state directory: no sudo, no helper, no /etc/pve. Registration survives a restart.
func TestRegionDaemonKeepsStateAcrossRestart(t *testing.T) {
	dir := privateDir(t)
	binary := filepath.Join(dir, "vws-region")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/vws-region")
	build.Dir = "../../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	stateDir := filepath.Join(dir, "state")
	tlsConfig := daemonCertificates(t, dir)
	s := scenario()
	s.Pools = []string{"123456789012"}
	s.Roles[0].Privs = append(s.Roles[0].Privs, "Pool.Audit")
	fake, err := pvefake.New(s)
	if err != nil {
		t.Fatal(err)
	}
	var unavailable atomic.Bool
	pve := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unavailable.Load() {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fake.ServeHTTP(w, r)
	}))
	pve.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: tlsConfig.Certificates}
	pve.StartTLS()
	defer pve.Close()
	writeFixture(t, filepath.Join(dir, "region.yaml"), []byte("read_only: true\npools:\n  project: '123456789012'\n"))
	const canary = "fake-secret"
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	request := func(t *testing.T, method, url, data string, want int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, url, strings.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		res, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if bytes.Contains(body, []byte(canary)) {
			t.Fatal("token in response")
		}
		if err != nil || res.StatusCode != want {
			t.Fatalf("status=%d body=%s err=%v", res.StatusCode, body, err)
		}
		return body
	}
	start := func(region string) (string, string, func()) {
		addr, ops := unusedAddress(t), unusedAddress(t)
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Minute)
		cmd := exec.CommandContext(ctx, binary,
			"-config", filepath.Join(dir, "region.yaml"), "-region", region, "-state-dir", stateDir,
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
			if strings.Contains(output.String(), canary) {
				t.Error("token in daemon log")
			}
		}
		t.Cleanup(stop)
		return "https://" + addr, "http://" + ops, stop
	}
	first, ops, stop := start("pve-test-1")
	awaitStatus(t, ops+"/readyz", http.StatusServiceUnavailable)
	body := request(t, http.MethodGet, ops+"/readyz", "", http.StatusServiceUnavailable)
	if string(body) != "unregistered\n" {
		t.Fatalf("unregistered readiness = %q", body)
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	put := func(origin, region string, want int) {
		t.Helper()
		request(t, http.MethodPut, origin+"/internal/v1/registration", `{"region":"`+region+
			`","cluster_name":"test","pveApiUrls":["`+pve.URL+`"],"caPem":`+strconv.Quote(string(caPEM))+
			`,"tokenId":"vws@pve!inventory","token":"`+canary+
			`","zones":[{"letter":"a","nodes":["pve1"]}]}`, want)
	}
	put(first, "other-region", http.StatusBadRequest)
	if _, err := os.Stat(filepath.Join(stateDir, registrationFile)); !os.IsNotExist(err) {
		t.Fatalf("a registration for another region reached the state file: %v", err)
	}
	put(first, "pve-test-1", http.StatusOK)
	awaitStatus(t, ops+"/readyz", http.StatusOK)
	info, err := os.Stat(filepath.Join(stateDir, registrationFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v, %v", info, err)
	}
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	read := func(origin string) resource.Page[resource.Instance] {
		var page resource.Page[resource.Instance]
		data := `{"scope":{"account":"` + account.String() + `","pool":"123456789012"},"req":{}}`
		if err := json.Unmarshal(request(t, http.MethodPost, origin+"/internal/v1/Compute/DescribeInstances",
			data, http.StatusOK), &page); err != nil {
			t.Fatal(err)
		}
		return page
	}
	want := read(first)
	unavailable.Store(true)
	awaitStatus(t, ops+"/readyz", http.StatusServiceUnavailable)
	var failure struct {
		Error *resource.Error `json:"error"`
	}
	body = request(t, http.MethodGet, first+"/internal/v1/status", "", http.StatusServiceUnavailable)
	if err := json.Unmarshal(body, &failure); err != nil || failure.Error == nil ||
		failure.Error.Message != "registration self-check failed: privileges" {
		t.Fatalf("readiness lost its safe reason: %s (%v)", body, err)
	}
	unavailable.Store(false)
	awaitStatus(t, ops+"/readyz", http.StatusOK)
	stop()
	restarted, restartOps, _ := start("pve-test-1")
	awaitStatus(t, restartOps+"/readyz", http.StatusOK)
	if got := read(restarted); !reflect.DeepEqual(got, want) {
		t.Fatalf("restart changed inventory: got=%+v want=%+v", got, want)
	}
	for _, method := range fake.RequestMethods() {
		if !strings.EqualFold(method, http.MethodGet) {
			t.Fatalf("PVE mutation: %s", method)
		}
	}
	files, err := os.ReadDir(stateDir)
	if err != nil || len(files) != 1 {
		t.Fatalf("state directory holds more than the state file: %v %v", files, err)
	}
}
