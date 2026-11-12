package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/grpcclient/iamclient"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
)

func regionTLSFiles(t *testing.T, srv *httptest.Server) iamclient.TLSFiles {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	key, err := x509.MarshalPKCS8PrivateKey(srv.TLS.Certificates[0].PrivateKey)
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
	return iamclient.TLSFiles{CAFile: certPath, CertFile: certPath, KeyFile: keyPath}
}

func TestRegionHealthUsesBootstrapMTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/v1/pools/project" && r.Method == http.MethodGet {
			w.Write([]byte(`{"exists":true}`))
			return
		}
		if r.URL.Path == "/internal/v1/registration" && r.Method == http.MethodPut {
			w.Write([]byte(`{}`))
			return
		}
		if r.URL.Path != "/internal/v1/status" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte(`{"quorate":true,"leader":null,"nodes":[],"lastError":null}`))
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()
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
	files, err := regionMTLSFiles(path, iamclient.TLSFiles{})
	if err != nil {
		t.Fatal(err)
	}
	health := regionHealth(files)
	got, err := health(t.Context(), srv.URL)
	if err != nil || !got.Quorate || got.Nodes == nil {
		t.Fatalf("bootstrap health: %+v %v", got, err)
	}
	register := regionRegistration(files)
	if err := register(t.Context(), srv.URL, []byte(`{}`)); err != nil {
		t.Fatalf("bootstrap registration: %v", err)
	}
	pool := regionPool(files)
	if exists, err := pool(t.Context(), srv.URL, "project"); err != nil || !exists {
		t.Fatalf("bootstrap pool: %t %v", exists, err)
	}
	if _, err := health(t.Context(), "https://user:credential@127.0.0.1:1234"); err == nil ||
		strings.Contains(err.Error(), "credential") || strings.Contains(err.Error(), "user:") {
		t.Fatalf("credential-bearing region endpoint was not safely refused: %v", err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := health(t.Context(), srv.URL); err == nil || err.Error() != "region mTLS configuration failed" {
		t.Fatalf("missing client key was not safely refused: %v", err)
	}
	if _, err := pool(t.Context(), srv.URL, "project"); err == nil ||
		err.Error() != "region mTLS configuration failed" {
		t.Fatalf("pool accepted missing client key: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("credential-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := health(t.Context(), srv.URL); err == nil || err.Error() != "region mTLS configuration failed" {
		t.Fatalf("invalid client key was not safely refused: %v", err)
	}
}

func TestRegionHealthRequiresBootstrapCredentials(t *testing.T) {
	health := regionHealth(iamclient.TLSFiles{})
	_, err := health(t.Context(), "https://127.0.0.1:1234")
	var config *console.RegionMTLSConfigError
	if !errors.As(err, &config) || config.Err.Error() != "mTLS is not configured" {
		t.Fatalf("missing bootstrap credentials: %v", err)
	}
	if _, err := regionMTLSFiles(filepath.Join(t.TempDir(), "missing"), iamclient.TLSFiles{}); err == nil {
		t.Fatal("missing bootstrap file accepted")
	}
}

func TestRegionHealthUsesExplicitMTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/status":
			w.Write([]byte(`{"quorate":true,"leader":null,"nodes":[],"lastError":null}`))
		case "/internal/v1/registration":
			w.Write([]byte(`{}`))
		case "/internal/v1/pools/project":
			w.Write([]byte(`{"exists":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()
	defer srv.Close()
	files := regionTLSFiles(t, srv)
	for _, field := range []string{"valid", "ca", "cert", "key"} {
		t.Run(field, func(t *testing.T) {
			input := files
			missing := filepath.Join(t.TempDir(), "missing")
			switch field {
			case "ca":
				input.CAFile = missing
			case "cert":
				input.CertFile = missing
			case "key":
				input.KeyFile = missing
			}
			health := regionHealth(input)
			got, err := health(t.Context(), srv.URL)
			if field == "valid" {
				if err != nil || !got.Quorate {
					t.Fatalf("explicit mTLS health: %+v %v", got, err)
				}
				if err := regionRegistration(input)(t.Context(), srv.URL, []byte(`{}`)); err != nil {
					t.Fatalf("explicit mTLS registration: %v", err)
				}
				if exists, err := regionPool(input)(t.Context(), srv.URL, "project"); err != nil || !exists {
					t.Fatalf("explicit mTLS pool: %t %v", exists, err)
				}
			} else if err == nil || err.Error() != "region mTLS configuration failed" {
				t.Fatalf("missing %s accepted or exposed: %v", field, err)
			}
		})
	}
}
