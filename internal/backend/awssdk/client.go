// Package awssdk reads AWS inventory through the credential-isolated forwarding proxy.
package awssdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/popododo0720/vws-lib/obs"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const callTimeout = 30 * time.Second

// Config binds one registered AWS account and region to the local proxy.
type Config struct {
	Socket    string
	Account   string
	Region    string
	Principal func(context.Context) string
}

// Backend holds no AWS credential provider other than anonymous credentials.
type Backend struct {
	backend.AllSupported
	client    *ec2.Client
	transport *http.Transport
	region    string
}

// New creates an SDK client that cannot connect outside the proxy socket.
func New(cfg Config) (*Backend, error) {
	if !filepath.IsAbs(cfg.Socket) || filepath.Clean(cfg.Socket) != cfg.Socket ||
		!regexp.MustCompile(`^[0-9]{12}$`).MatchString(cfg.Account) ||
		len(cfg.Region) > 32 || !regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`).MatchString(cfg.Region) ||
		cfg.Principal == nil {
		return nil, resource.Invalid("awssdk", "socket, account, region and principal source are required")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", cfg.Socket)
			if err != nil {
				return nil, fmt.Errorf("awssdk: dial proxy: %w", err)
			}
			return conn, nil
		},
		ResponseHeaderTimeout: 5 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		MaxConnsPerHost:       32,
	}
	client := &http.Client{
		Timeout:   callTimeout,
		Transport: otelhttp.NewTransport(forwardingTransport{base: transport, cfg: cfg}),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Backend{
		AllSupported: backend.AllSupported{Kind: resource.RegionKindAWS},
		transport:    transport, region: cfg.Region,
		client: ec2.New(ec2.Options{
			Region: cfg.Region, Credentials: aws.AnonymousCredentials{},
			BaseEndpoint: aws.String("http://proxy/"), HTTPClient: client, RetryMaxAttempts: 3,
		}),
	}, nil
}

// Close releases idle connections to the proxy.
func (b *Backend) Close() { b.transport.CloseIdleConnections() }

type forwardingTransport struct {
	base *http.Transport
	cfg  Config
}

func (f forwardingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	req := r.Clone(r.Context())
	req.Header.Set("X-Vws-Account", f.cfg.Account)
	req.Header.Set("X-Vws-Principal", f.cfg.Principal(r.Context()))
	req.Header.Set("X-Vws-Target-Region", f.cfg.Region)
	req.Header.Set("X-Vws-Target-Service", "ec2")
	req.Header.Set("X-Vws-Request-Id", obs.RequestID(r.Context()))
	resp, err := f.base.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("awssdk: forward request: %w", err)
	}
	return resp, nil
}

func awsError(err error) error {
	var api smithy.APIError
	if errors.As(err, &api) {
		code := resource.CodeInvalidArgument
		var response *smithyhttp.ResponseError
		if errors.As(err, &response) {
			switch {
			case response.HTTPStatusCode() == http.StatusTooManyRequests:
				code = resource.CodeResourceExhausted
			case response.HTTPStatusCode() >= http.StatusInternalServerError:
				code = resource.CodeUnavailable
			}
		}
		switch api.ErrorCode() {
		case "UnauthorizedOperation", "AuthFailure", "AccessDenied":
			code = resource.CodePermissionDenied
		case "RequestLimitExceeded", "Throttling", "ThrottlingException":
			code = resource.CodeResourceExhausted
		}
		return (&resource.Error{Code: code, Message: api.ErrorCode() + ": " + api.ErrorMessage()}).WithCause(err)
	}
	return (&resource.Error{Code: resource.CodeUnavailable, Message: "AWS inventory unavailable"}).WithCause(err)
}
