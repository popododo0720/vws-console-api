package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegionHealthUsesBootstrapMTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/status" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte(`{"quorate":true,"leader":null,"nodes":[],"lastError":null}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	cert := srv.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{
		certPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}),
		keyPath:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "global.yaml")
	data := fmt.Sprintf(`iam:
  etcd_endpoints: [https://127.0.0.1:2379]
  tls: {ca_file: %s}
credentials:
  kek_file: %s
  mtls: {ca_file: %s, cert_file: %s, key_file: %s}
default_project: default
`, certPath, filepath.Join(dir, "kek"), certPath, certPath, keyPath)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	health, err := regionHealth(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := health(t.Context(), srv.URL)
	if err != nil || !got.Quorate || got.Nodes == nil {
		t.Fatalf("bootstrap health: %+v %v", got, err)
	}
	if _, err := health(t.Context(), "https://user:credential@127.0.0.1:1234"); err == nil ||
		strings.Contains(err.Error(), "credential") || strings.Contains(err.Error(), "user:") {
		t.Fatalf("credential-bearing region endpoint was not safely refused: %v", err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := health(t.Context(), srv.URL); err == nil {
		t.Fatal("missing client key accepted")
	}
}

func TestRegionHealthRequiresBootstrapCredentials(t *testing.T) {
	health, err := regionHealth("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := health(t.Context(), "https://127.0.0.1:1234"); err == nil {
		t.Fatal("missing bootstrap credentials accepted")
	}
	if _, err := regionHealth(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing bootstrap file accepted")
	}
}
