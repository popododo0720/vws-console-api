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
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Client calls a region over an authenticated TLS connection.
type Client struct {
	base string
	http *http.Client
}

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

// Call executes one read and decodes its resource result into dst.
func (c *Client) Call(ctx context.Context, iface, method string, scope backend.Scope, req, dst any) error {
	data, err := json.Marshal(struct {
		Scope backend.Scope `json:"scope"`
		Req   any           `json:"req"`
	}{Scope: scope, Req: req})
	if err != nil {
		return fmt.Errorf("encode region request: %w", err)
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
	const maxResponseBytes = 8 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read region response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return resource.TooLarge("region response exceeds the limit")
	}
	if resp.StatusCode != http.StatusOK {
		var envelope errorBody
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("decode region error: %w", err)
		}
		for _, code := range append(resource.Codes(), resource.CodeUnspecified) {
			if code.String() == envelope.Error.Code {
				e := &resource.Error{
					Code: code, Message: envelope.Error.Message,
					ID: envelope.Error.ID, Field: envelope.Error.Field,
				}
				for _, kind := range resource.Kinds() {
					if kind.String() == envelope.Error.Kind {
						e.Kind = kind
						break
					}
				}
				return e
			}
		}
		return resource.Internal(fmt.Errorf("unknown region error code %q", envelope.Error.Code))
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("decode region result: %w", err)
	}
	return nil
}
