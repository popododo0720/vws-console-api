package regionapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Client calls a region over an authenticated TLS connection.
type Client struct {
	base string
	http *http.Client
}

// JSON escapes a tag rune to at most six bytes. A page has at most 100
// resources, each with 50 tags of 128/256 runes. Reserve 1 KiB per fixed
// record, interface, volume and rule, plus 1 MiB for the envelope and cursor.
const maxResponseBytes = 100*(resource.MaxTags*(6*(128+256)+8)+
	1024*(1+resource.MaxNetworkInterfaces+resource.MaxLaunchVolumes+resource.MaxIngressRules)) + (1 << 20)

// NewClient requires an HTTPS origin and a configuration with client identity.
func NewClient(base string, config *tls.Config) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, resource.Invalid("url", "expected an HTTPS origin")
	}
	if config == nil || config.InsecureSkipVerify || len(config.Certificates) == 0 {
		return nil, resource.Invalid("tls", "verified TLS with a client certificate is required")
	}
	transport := &http.Transport{
		TLSClientConfig: config.Clone(), TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second, IdleConnTimeout: 120 * time.Second,
	}
	return &Client{base: "https://" + u.Host, http: &http.Client{
		Transport: transport, Timeout: 60 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// Close releases pooled idle connections.
func (c *Client) Close() { c.http.CloseIdleConnections() }

// Register forwards a registration to the region without retaining its token.
func (c *Client) Register(ctx context.Context, data json.RawMessage) error {
	var result struct{}
	return c.do(ctx, http.MethodPut, "/internal/v1/registration", data, &result)
}

// Status returns the region's live quorum and node availability.
func (c *Client) Status(ctx context.Context) (resource.RegionStatus, error) {
	var result resource.RegionStatus
	err := c.do(ctx, http.MethodGet, "/internal/v1/status", nil, &result)
	return result, err
}

// Call executes a scoped read or mutation and decodes its result into dst.
func (c *Client) Call(ctx context.Context, iface, method string, scope, req, dst any) error {
	envelope := struct {
		Scope    any `json:"scope,omitempty"`
		Mutation any `json:"mutation,omitempty"`
		Req      any `json:"req"`
	}{Req: req}
	switch scope := scope.(type) {
	case backend.Scope:
		envelope.Scope = scope
	case backend.Mutation:
		envelope.Mutation = scope
	default:
		return resource.Invalid("scope", "expected scope or mutation")
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode region request: %w", err)
	}
	if len(data) > requestLimit(iface, method) {
		return resource.TooLarge("body exceeds the limit")
	}
	return c.do(ctx, http.MethodPost, "/internal/v1/"+iface+"/"+method, data, dst)
}

// Capabilities returns the region's current capability document.
func (c *Client) Capabilities(ctx context.Context) (resource.RegionCapabilities, error) {
	var result resource.RegionCapabilities
	err := c.do(ctx, http.MethodGet, "/internal/v1/capabilities", nil, &result)
	return result, err
}

// Version returns the release line and cluster name used for the handshake.
func (c *Client) Version(ctx context.Context) (Version, error) {
	var result Version
	err := c.do(ctx, http.MethodGet, "/internal/v1/version", nil, &result)
	return result, err
}

func (c *Client) do(ctx context.Context, method, path string, data []byte, dst any) (retErr error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build region request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("call region: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, resp.Body.Close()) }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read region response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return resource.TooLarge("region response exceeds the limit")
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusServiceUnavailable && strings.TrimSpace(string(body)) == "region not ready" {
			return &resource.Error{Code: resource.CodeUnavailable, Message: "not ready"}
		}
		var envelope errorBody
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("decode region error: %w", err)
		}
		if envelope.Error == nil {
			return resource.Internal(fmt.Errorf("missing region error"))
		}
		return envelope.Error
	}
	if err := decodeResult(body, dst); err != nil {
		return fmt.Errorf("decode region result: %w", err)
	}
	if stale, ok := dst.(interface{ SetStale(bool) }); ok {
		stale.SetStale(resp.Header.Get("X-Vws-Stale") == "true")
	}
	return nil
}
