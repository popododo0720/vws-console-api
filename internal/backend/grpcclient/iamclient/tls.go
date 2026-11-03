package iamclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// TLSFiles names the PEM files that secure the connection to vws-iam. They
// are usually mounted from a Kubernetes Secret. The zero value means
// plaintext.
type TLSFiles struct {
	// CAFile is the bundle that verifies the vws-iam server certificate.
	// Setting it turns TLS on.
	CAFile string
	// CertFile and KeyFile are the client certificate and key for mutual
	// TLS. Set both or neither. They are read again on every handshake, so
	// a rotated Secret takes effect on the next connection without a
	// restart.
	CertFile string
	KeyFile  string
	// ServerName overrides the name checked against the server
	// certificate. Empty uses the host of the dial target.
	ServerName string
}

// Enabled reports whether any TLS setting is present.
func (f TLSFiles) Enabled() bool {
	return f.CAFile != "" || f.CertFile != "" || f.KeyFile != "" || f.ServerName != ""
}

// Config builds the client TLS configuration. It fails when a file is
// missing or invalid, so a bad mount stops the process at start instead of
// on the first request.
func (f TLSFiles) Config() (*tls.Config, error) {
	if f.CAFile == "" {
		return nil, errors.New("vws-iam TLS needs a CA file")
	}
	if (f.CertFile == "") != (f.KeyFile == "") {
		return nil, errors.New("vws-iam mutual TLS needs both a client certificate and a key file")
	}
	pem, err := os.ReadFile(f.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read vws-iam CA file: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("vws-iam CA file %s holds no PEM certificate", f.CAFile)
	}
	cfg := &tls.Config{RootCAs: roots, ServerName: f.ServerName, MinVersion: tls.VersionTLS12}
	if f.CertFile == "" {
		return cfg, nil
	}
	if _, err := f.clientCertificate(); err != nil {
		return nil, err
	}
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return f.clientCertificate()
	}
	return cfg, nil
}

func (f TLSFiles) clientCertificate() (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(f.CertFile, f.KeyFile)
	if err != nil {
		// The error names the files, never their contents.
		return nil, fmt.Errorf("load vws-iam client certificate: %w", err)
	}
	return &cert, nil
}
