package iamclient

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// pki is a throwaway CA with one server and one client certificate, written
// as PEM files the way a mounted Secret holds them.
type pki struct {
	dir                  string
	caFile               string
	serverCert           tls.Certificate
	clientCert, clientKy string
	pool                 *x509.CertPool
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	dir := t.TempDir()
	caKey := newKey(t)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vws-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	p := &pki{dir: dir, caFile: filepath.Join(dir, "ca.crt"), pool: x509.NewCertPool()}
	p.pool.AddCert(ca)
	writePEM(t, p.caFile, "CERTIFICATE", caDER)

	issue := func(
		serial int64, cn string, usage x509.ExtKeyUsage, ips []net.IP, dns []string,
	) ([]byte, *ecdsa.PrivateKey) {
		key := newKey(t)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature,
			IPAddresses: ips, DNSNames: dns,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, key
	}
	srvDER, srvKey := issue(2, "vws-iam", x509.ExtKeyUsageServerAuth,
		[]net.IP{net.IPv4(127, 0, 0, 1)}, []string{"vws-iam.vws-system"})
	p.serverCert = tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}
	p.clientCert, p.clientKy = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	p.writeClient(t, issue, 3)
	return p
}

type issuer func(
	serial int64, cn string, usage x509.ExtKeyUsage, ips []net.IP, dns []string,
) ([]byte, *ecdsa.PrivateKey)

func (p *pki) writeClient(t *testing.T, issue issuer, serial int64) {
	t.Helper()
	der, key := issue(serial, "vws-console-api", x509.ExtKeyUsageClientAuth, nil, nil)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, p.clientCert, "CERTIFICATE", der)
	writePEM(t, p.clientKy, "PRIVATE KEY", keyDER)
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// serveTLS runs a fake vws-iam AuthService on 127.0.0.1 behind TLS. With
// clientCAs set it requires a client certificate signed by them.
func serveTLS(t *testing.T, p *pki, clientCAs *x509.CertPool) (string, *server) {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{p.serverCert}, MinVersion: tls.VersionTLS12}
	if clientCAs != nil {
		cfg.ClientCAs, cfg.ClientAuth = clientCAs, tls.RequireAndVerifyClientCert
	}
	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{decision: iamv1.Decision_DECISION_ALLOW, authnResult: &iamv1.AuthenticateResponse{
		Account: "123456789012", Arn: "arn:vws:iam::123456789012:user/eng/bob",
		Principal: &iamv1.Principal{
			Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: "arn:vws:iam::123456789012:user/eng/bob",
			Project: "123456789012", UniqueId: "AIDABOB", Resource: "projects/123456789012/users/bob",
		},
	}}
	g := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	iamv1.RegisterAuthServiceServer(g, s)
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Stop)
	return lis.Addr().String(), s
}

func dialTLS(t *testing.T, target string, files TLSFiles) *Client {
	t.Helper()
	cfg, err := files.Config()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Dial(target, WithTLS(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestDialTLSVerifiesTheServerWithTheConfiguredCA(t *testing.T) {
	p := newPKI(t)
	target, s := serveTLS(t, p, nil)
	c := dialTLS(t, target, TLSFiles{CAFile: p.caFile})
	got, err := c.Authenticate(t.Context(), signed)
	if err != nil {
		t.Fatalf("Authenticate over TLS: %v", err)
	}
	if got.ARN != "arn:vws:iam::123456789012:user/eng/bob" || len(s.authn) != 1 {
		t.Fatalf("principal %+v after %d calls", got, len(s.authn))
	}
}

func TestDialTLSChecksTheServerName(t *testing.T) {
	p := newPKI(t)
	target, _ := serveTLS(t, p, nil)
	// The certificate names vws-iam.vws-system, not the override.
	c := dialTLS(t, target, TLSFiles{CAFile: p.caFile, ServerName: "evil.example"})
	if _, err := c.Authenticate(t.Context(), signed); err == nil {
		t.Fatal("Authenticate succeeded against a certificate for another name")
	}
	ok := dialTLS(t, target, TLSFiles{CAFile: p.caFile, ServerName: "vws-iam.vws-system"})
	if _, err := ok.Authenticate(t.Context(), signed); err != nil {
		t.Fatalf("Authenticate with the certificate's name: %v", err)
	}
}

func TestDialTLSRejectsAServerFromAnotherCA(t *testing.T) {
	trusted, other := newPKI(t), newPKI(t)
	target, s := serveTLS(t, other, nil)
	c := dialTLS(t, target, TLSFiles{CAFile: trusted.caFile})
	if _, err := c.Authenticate(t.Context(), signed); err == nil {
		t.Fatal("Authenticate succeeded against a server the CA did not sign")
	}
	if len(s.authn) != 0 {
		t.Fatalf("the untrusted server got %d requests", len(s.authn))
	}
}

func TestDialMutualTLS(t *testing.T) {
	p := newPKI(t)
	target, s := serveTLS(t, p, p.pool)
	c := dialTLS(t, target, TLSFiles{CAFile: p.caFile, CertFile: p.clientCert, KeyFile: p.clientKy})
	if _, err := c.Authenticate(t.Context(), signed); err != nil {
		t.Fatalf("Authenticate over mutual TLS: %v", err)
	}
	noCert := dialTLS(t, target, TLSFiles{CAFile: p.caFile})
	if _, err := noCert.Authenticate(t.Context(), signed); err == nil {
		t.Fatal("a server requiring a client certificate accepted a client without one")
	}
	if len(s.authn) != 1 {
		t.Fatalf("server got %d requests, want only the one with a client certificate", len(s.authn))
	}
}

// A rotated client certificate is used on the next handshake without
// rebuilding the configuration.
func TestClientCertificateIsReadOnEveryHandshake(t *testing.T) {
	p := newPKI(t)
	cfg, err := TLSFiles{CAFile: p.caFile, CertFile: p.clientCert, KeyFile: p.clientKy}.Config()
	if err != nil {
		t.Fatal(err)
	}
	first, err := cfg.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	rotated := newPKI(t)
	for _, f := range [][2]string{{rotated.clientCert, p.clientCert}, {rotated.clientKy, p.clientKy}} {
		b, err := os.ReadFile(f[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f[1], b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	second, err := cfg.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("the handshake still presents the certificate from before the rotation")
	}
}

func TestTLSFilesConfigRejectsBadSettings(t *testing.T) {
	p := newPKI(t)
	notPEM := filepath.Join(p.dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		files TLSFiles
		want  string
	}{
		"no CA":            {TLSFiles{ServerName: "vws-iam"}, "needs a CA file"},
		"cert without key": {TLSFiles{CAFile: p.caFile, CertFile: p.clientCert}, "both a client certificate and a key"},
		"key without cert": {TLSFiles{CAFile: p.caFile, KeyFile: p.clientKy}, "both a client certificate and a key"},
		"missing CA file":  {TLSFiles{CAFile: filepath.Join(p.dir, "absent.crt")}, "read vws-iam CA file"},
		"CA not PEM":       {TLSFiles{CAFile: notPEM}, "holds no PEM certificate"},
		"bad key pair": {
			TLSFiles{CAFile: p.caFile, CertFile: p.clientCert, KeyFile: notPEM}, "load vws-iam client certificate",
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := tc.files.Config()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Config() = %v, %v; want error containing %q", cfg, err, tc.want)
			}
		})
	}
	if (TLSFiles{}).Enabled() {
		t.Fatal("the zero TLSFiles is not plaintext")
	}
	cfg, err := TLSFiles{CAFile: p.caFile}.Config()
	if err != nil || cfg.MinVersion != tls.VersionTLS12 || cfg.GetClientCertificate != nil {
		t.Fatalf("server-only TLS config %+v, %v", cfg, err)
	}
}
