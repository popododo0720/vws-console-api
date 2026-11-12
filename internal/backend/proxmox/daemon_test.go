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
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
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

func TestRegionDaemonReadsRestartAndReadiness(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "vws-region")
	build := exec.CommandContext(t.Context(), "go", "build", "-race", "-o", binary, "./cmd/vws-region")
	build.Dir = "../../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	helper := filepath.Join(dir, "helper")
	build = exec.CommandContext(t.Context(), "go", "test", "-c", "-o", helper, "./internal/regionhelper")
	build.Dir = "../../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("helper build: %v\n%s", err, out)
	}
	for _, name := range []string{"public", "private", "locks"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFixture(t, filepath.Join(dir, "region-kek"), bytes.Repeat([]byte{42}, 32))
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	t.Setenv("VWS_HELPER_TEST_ROOT", dir)
	tlsConfig := daemonCertificates(t, dir)
	s := scenario()
	next := s.Tokens[0]
	next.ID, next.Secret = "vws@pve!next", "replacement-secret"
	s.Tokens = append(s.Tokens, next)
	fake, err := pvefake.New(s)
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
	reg := filepath.Join(dir, "public", "registration.json")
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
		if bytes.Contains(body, []byte(canary)) || bytes.Contains(body, []byte(next.Secret)) {
			t.Fatal("token in response")
		}
		if err != nil || res.StatusCode != want {
			t.Fatalf("status=%d body=%s err=%v", res.StatusCode, body, err)
		}
		return body
	}
	start := func() (string, string, func()) {
		addr, ops := unusedAddress(t), unusedAddress(t)
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Minute)
		cmd := exec.CommandContext(ctx, binary,
			"-config", filepath.Join(dir, "region.yaml"), "-registration-file", reg,
			"-helper-path", helper,
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
			if strings.Contains(output.String(), canary) || strings.Contains(output.String(), next.Secret) {
				t.Error("token in daemon log")
			}
		}
		t.Cleanup(stop)
		return "https://" + addr, "http://" + ops, stop
	}
	first, ops, stop := start()
	awaitStatus(t, ops+"/readyz", http.StatusServiceUnavailable)
	second, secondOps, _ := start()
	awaitStatus(t, secondOps+"/readyz", http.StatusServiceUnavailable)
	body := request(t, http.MethodGet, ops+"/readyz", "", http.StatusServiceUnavailable)
	if string(body) != "unregistered\n" {
		t.Fatalf("unregistered readiness = %q", body)
	}
	close(gate)
	tokenID, token := "vws@pve!inventory", canary
	put := func(t *testing.T, cluster, id, secret string, want int) {
		t.Helper()
		data := `{"region":"pve-test-1","cluster_name":"` + cluster +
			`","tokenId":"` + id + `","token":"` + secret + `","zones":[{"letter":"a","nodes":["pve1"]}]}`
		if cluster == "test" {
			zones := registrationZones(990)
			input := map[string]any{
				"region": "pve-test-1", "cluster_name": cluster, "tokenId": id, "token": secret, "zones": zones,
			}
			body, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			last := &zones[len(zones)-1].Nodes[len(zones[len(zones)-1].Nodes)-1]
			excess := len(body) - (64 << 10)
			if excess < 0 || excess >= len(*last) {
				t.Fatal("maximum-size fixture cannot trim its final node")
			}
			*last = (*last)[excess:]
			body, err = json.Marshal(input)
			if err != nil || len(body) != 64<<10 {
				t.Fatalf("request bytes=%d err=%v", len(body), err)
			}
			data = string(body)
		}
		request(t, http.MethodPut, first+"/internal/v1/registration", data, want)
	}
	put(t, "wrong", tokenID, token, http.StatusConflict)
	for _, name := range []string{"public", "private", "locks"} {
		files, err := os.ReadDir(filepath.Join(dir, name))
		if err != nil || len(files) != 0 {
			t.Fatalf("mismatch wrote %s: %v", name, err)
		}
	}
	conn, err := Open(filepath.Join(dir, "region.yaml"), reg, pve.URL, pve.Client())
	if err != nil {
		t.Fatal(err)
	}
	conn.Helper.Path = helper
	t.Run("omitted_token_requires_registration", func(t *testing.T) {
		input := []byte(`{"region":"pve-test-1","cluster_name":"test","tokenId":"vws@pve!inventory"}`)
		err := conn.Register(t.Context(), input)
		if e := resource.AsError(err); e.Code != resource.CodeInvalidArgument || e.Field != "token" {
			t.Fatalf("first registration without token: %v", err)
		}
	})
	t.Run("invalid_tokens", func(t *testing.T) {
		before := len(fake.Requests())
		for _, token := range []string{"", "contains space", "newline\n", strings.Repeat("a", 513)} {
			s := registrationSnapshot{
				Region: "pve-test-1", ClusterName: "test", TokenID: "vws@pve!inventory", Token: pveclient.Secret(token),
			}
			if _, err := conn.check(t.Context(), s); resource.CodeOf(err) != resource.CodeInvalidArgument {
				t.Fatalf("invalid token error = %v, want InvalidArgument", err)
			}
		}
		if len(fake.Requests()) != before {
			t.Fatal("invalid token reached PVE")
		}
	})
	t.Run("oversized_identity", func(t *testing.T) {
		data, err := json.Marshal(map[string]any{
			"region": "pve-test-1", "cluster_name": "test", "tokenId": tokenID, "token": token,
			"zones": registrationZones(1024),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Register(t.Context(), data); resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Fatalf("oversized identity error=%v, want InvalidArgument", err)
		}
		for _, name := range []string{"public", "private", "locks"} {
			files, err := os.ReadDir(filepath.Join(dir, name))
			if err != nil || len(files) != 0 {
				t.Fatalf("oversized identity wrote %s: %v", name, err)
			}
		}
	})
	put(t, "test", tokenID, token, http.StatusOK)
	put(t, "test", tokenID, token, http.StatusOK)
	t.Run("omitted_token_reuses_without_write", func(t *testing.T) {
		before, err := os.ReadFile(filepath.Join(dir, "private", "pve-token"))
		if err != nil {
			t.Fatal(err)
		}
		writeFixture(t, filepath.Join(dir, "fail"), []byte("token-write"))
		request(t, http.MethodPut, first+"/internal/v1/registration",
			`{"region":"pve-test-1","cluster_name":"test","tokenId":"vws@pve!inventory"}`, http.StatusOK)
		after, err := os.ReadFile(filepath.Join(dir, "private", "pve-token"))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("omitted token rewrote encrypted token")
		}
		if err := os.Remove(filepath.Join(dir, "fail")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("omitted_token_rejects_mismatch", func(t *testing.T) {
		before, err := os.ReadFile(reg)
		if err != nil {
			t.Fatal(err)
		}
		var stored registrationSnapshot
		if err := json.Unmarshal(before, &stored); err != nil {
			t.Fatal(err)
		}
		stored.Fingerprint = "mismatch"
		data, err := json.Marshal(stored)
		if err != nil {
			t.Fatal(err)
		}
		writeFixture(t, reg, data)
		input := []byte(`{"region":"pve-test-1","cluster_name":"test","tokenId":"vws@pve!inventory"}`)
		err = conn.Register(t.Context(), input)
		if e := resource.AsError(err); e.Code != resource.CodeInvalidArgument || e.Field != "token" {
			t.Fatalf("fingerprint mismatch: %v", err)
		}
		writeFixture(t, reg, before)
	})
	put(t, "test", tokenID, token, http.StatusOK)
	awaitStatus(t, ops+"/readyz", http.StatusOK)
	awaitStatus(t, secondOps+"/readyz", http.StatusOK)
	awaitStatus(t, ops+"/healthz", http.StatusOK)
	awaitStatus(t, ops+"/metrics", http.StatusOK)
	var health resource.RegionStatus
	err = json.Unmarshal(request(t, http.MethodGet, first+"/internal/v1/status", "", http.StatusOK), &health)
	if err != nil || !health.Quorate || len(health.Nodes) != 1 || !health.Nodes[0].Online {
		t.Fatalf("daemon health=%+v err=%v", health, err)
	}
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	read := func(origin string) resource.Page[resource.Instance] {
		var page resource.Page[resource.Instance]
		data := `{"scope":{"account":"` + account.String() + `"},"req":{}}`
		if err := json.Unmarshal(request(t, http.MethodPost, origin+"/internal/v1/Compute/DescribeInstances",
			data, http.StatusOK), &page); err != nil {
			t.Fatal(err)
		}
		return page
	}
	want := read(first)
	if got := read(second); !reflect.DeepEqual(got, want) {
		t.Fatalf("two daemons disagree: got=%+v want=%+v", got, want)
	}
	var caps resource.RegionCapabilities
	err = json.Unmarshal(request(t, http.MethodGet, second+"/internal/v1/capabilities", "", http.StatusOK), &caps)
	if err != nil || caps.Region != "pve-test-1" {
		t.Fatalf("capabilities=%+v err=%v", caps, err)
	}
	for _, failure := range []struct {
		verb, id, secret string
		status           int
	}{
		{"registration-write", next.ID, next.Secret, http.StatusServiceUnavailable},
		{"unlock", tokenID, token, http.StatusOK},
	} {
		t.Run(failure.verb+"_failure", func(t *testing.T) {
			before, err := os.ReadFile(reg)
			if err != nil {
				t.Fatal(err)
			}
			writeFixture(t, filepath.Join(dir, "fail"), []byte(failure.verb))
			t.Cleanup(func() {
				if err := conn.Helper.Unlock(context.WithoutCancel(t.Context()), "registration"); err != nil {
					t.Error(err)
				}
			})
			put(t, "test", failure.id, failure.secret, failure.status)
			after, err := os.ReadFile(reg)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed operation changed the active registration")
			}
			if _, err := conn.Check(t.Context()); err != nil {
				t.Fatalf("previous token and registration no longer work: %v", err)
			}
		})
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
	for _, name := range []string{"public", "private", "locks"} {
		if err := filepath.WalkDir(filepath.Join(dir, name), func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			data, err := os.ReadFile(path)
			if bytes.Contains(data, []byte(canary)) || bytes.Contains(data, []byte(next.Secret)) {
				t.Errorf("plaintext token in %s", path)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}
