package awssdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/popododo0720/vws-lib/obs"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// ConnectionClient can reach only the private proxy socket and holds no AWS credentials.
type ConnectionClient struct {
	client    *http.Client
	transport *http.Transport
}

// NewConnectionClient refuses paths that could depend on the process working directory.
func NewConnectionClient(socket string) (*ConnectionClient, error) {
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || socket == "/" || len(socket) > 107 {
		return nil, resource.Invalid("socket", "absolute clean proxy socket path of at most 107 bytes required")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
			if err != nil {
				// Transport spans must not expose the operator's socket path.
				return nil, errors.New("AWS forwarding proxy unavailable")
			}
			return conn, nil
		},
		ResponseHeaderTimeout: 12 * time.Second, IdleConnTimeout: 30 * time.Second,
	}
	return &ConnectionClient{transport: transport, client: &http.Client{
		Timeout: 12 * time.Second, Transport: otelhttp.NewTransport(transport),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// Close releases idle socket connections when the console shuts down.
func (c *ConnectionClient) Close() { c.transport.CloseIdleConnections() }

// TestConnection accepts only fixed diagnostics, never raw proxy errors.
func (c *ConnectionClient) TestConnection(
	ctx context.Context, in resource.AWSConnectionRequest, principal string,
) []resource.ConnectionStep {
	body, err := json.Marshal(in)
	if err != nil {
		return unavailableSteps()
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://proxy/internal/v1/aws-accounts/test", bytes.NewReader(body))
	if err != nil {
		return unavailableSteps()
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Vws-Account", in.AccountID)
	r.Header.Set("X-Vws-Principal", principal)
	r.Header.Set("X-Vws-Target-Service", "sts")
	r.Header.Set("X-Vws-Request-Id", obs.RequestID(ctx))
	resp, err := c.client.Do(r)
	if err != nil {
		return unavailableSteps()
	}
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 4097))
	closeErr := resp.Body.Close()
	media, _, mediaErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if readErr != nil || closeErr != nil || len(data) > 4096 || resp.StatusCode != http.StatusOK ||
		mediaErr != nil || media != "application/json" {
		return unavailableSteps()
	}
	steps := decodeConnectionSteps(data)
	if resource.ValidAWSConnectionSteps(steps) {
		return steps
	}
	return unavailableSteps()
}

func unavailableSteps() []resource.ConnectionStep {
	steps := resource.AWSConnectionSteps(false, false)
	steps[0].Message = "AWS forwarding proxy unavailable"
	return steps
}

func decodeConnectionSteps(data []byte) []resource.ConnectionStep {
	dec := json.NewDecoder(bytes.NewReader(data))
	take := func(want any) bool {
		got, err := dec.Token()
		return err == nil && got == want
	}
	if !take(json.Delim('{')) || !take("steps") || !take(json.Delim('[')) {
		return nil
	}
	var steps []resource.ConnectionStep
	for dec.More() {
		if len(steps) == 2 || !take(json.Delim('{')) {
			return nil
		}
		var name, result, message string
		fields := map[string]*string{"name": &name, "result": &result, "message": &message}
		for dec.More() {
			key, err := dec.Token()
			field, ok := key.(string)
			if err != nil || !ok || fields[field] == nil || dec.Decode(fields[field]) != nil {
				return nil
			}
			delete(fields, field)
		}
		if len(fields) != 0 || !take(json.Delim('}')) {
			return nil
		}
		steps = append(steps, resource.ConnectionStep{
			Name: name, Result: resource.ConnectionResult(result), Message: message,
		})
	}
	if !take(json.Delim(']')) || !take(json.Delim('}')) {
		return nil
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil
	}
	return steps
}
