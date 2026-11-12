package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/grpcclient/iamclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox"
)

func standaloneBackend(
	ctx context.Context, config, registration, endpoint, ca, helper string,
) (*proxmox.Backend, func(), error) {
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	conn, err := proxmox.Open(config, registration, endpoint, client)
	if err != nil {
		return nil, nil, fmt.Errorf("-backend=proxmox requires region.yaml at -region-config: %w", err)
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, nil, fmt.Errorf("pve-endpoint requires an HTTPS origin without credentials")
	}
	tlsConfig, err := (iamclient.TLSFiles{CAFile: ca}).Config()
	if err != nil {
		return nil, nil, fmt.Errorf("proxmox CA: %w", err)
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client.Transport = transport
	conn.Helper.Path = helper
	b, err := conn.Check(ctx)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, fmt.Errorf("proxmox startup: %w", err)
	}
	return b, transport.CloseIdleConnections, nil
}
