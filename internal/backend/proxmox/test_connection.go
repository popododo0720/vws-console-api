package proxmox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// ConnectionConfig is a request-scoped PVE connection, not persisted identity.
type ConnectionConfig struct {
	URL, CAPEM, ClusterName, TokenID string
	TokenSecret                      string `json:"-"`
}

// TestConnection checks PVE without constructing a backend or persisting credentials.
func TestConnection(ctx context.Context, cfg ConnectionConfig) []resource.ConnectionStep {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	steps := []resource.ConnectionStep{
		{Name: "tls", Result: resource.ConnectionSkipped, Message: "previous step failed"},
		{Name: "version", Result: resource.ConnectionSkipped, Message: "previous step failed"},
		{Name: "cluster_name", Result: resource.ConnectionSkipped, Message: "previous step failed"},
		{Name: "privileges", Result: resource.ConnectionSkipped, Message: "previous step failed"},
	}
	u, err := url.Parse(cfg.URL)
	steps[0].Result, steps[0].Message = resource.ConnectionFail, "PVE TLS handshake failed"
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return steps
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if cfg.CAPEM != "" {
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM([]byte(cfg.CAPEM)) {
			return steps
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: tlsConfig}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return steps
	}
	if err := conn.Close(); err != nil {
		return steps
	}
	steps[0].Result, steps[0].Message = resource.ConnectionPass, "PVE TLS certificate verified"
	transport := &http.Transport{
		TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 3 * time.Second,
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 30 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client, err := pveclient.New(pveclient.Config{
		BaseURL: cfg.URL, TokenID: cfg.TokenID, Secret: pveclient.Secret(cfg.TokenSecret),
		HTTPClient: &http.Client{
			Transport: transport, Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	})
	steps[1].Result, steps[1].Message = resource.ConnectionFail, "PVE version read failed"
	if err != nil {
		return steps
	}
	version, err := client.Version(ctx)
	if err != nil || version.Version == "" {
		return steps
	}
	steps[1].Result, steps[1].Message = resource.ConnectionPass, "PVE version read succeeded"
	steps[2].Result, steps[2].Message = resource.ConnectionFail, "cluster_name differs or could not be verified"
	rows, err := client.ClusterStatus(ctx)
	if err != nil {
		return steps
	}
	matched := false
	for _, row := range rows {
		if row.Type == "cluster" {
			if row.Name != cfg.ClusterName {
				return steps
			}
			matched = true
		}
	}
	if !matched {
		return steps
	}
	steps[2].Result, steps[2].Message = resource.ConnectionPass, "cluster_name matches"
	steps[3].Result, steps[3].Message = resource.ConnectionFail, "token permissions could not be verified"
	permissions, err := client.AccessPermissions(ctx, "")
	if err != nil || permissions == nil {
		return steps
	}
	for _, privileges := range permissions {
		for privilege := range privileges {
			if forbiddenPrivilege(privilege) {
				steps[3].Message = "token holds a privilege outside PVEAuditor read-only access"
				return steps
			}
		}
	}
	steps[3].Result, steps[3].Message = resource.ConnectionPass, "token privileges are read-only"
	return steps
}
