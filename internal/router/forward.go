package router

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/popododo0720/vws-lib/obs"
	"github.com/popododo0720/vws-lib/obs/report"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"

	"github.com/popododo0720/vws-console-api/internal/audit"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// Forwarder dials only the operator's proxy socket.
type Forwarder struct {
	transport *http.Transport
	audit     *audit.Logger
}

// NewForwarder uses the same Unix socket as the AWS inventory client.
func NewForwarder(socket string, logger *audit.Logger) *Forwarder {
	return &Forwarder{audit: logger, transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
			if err != nil {
				return nil, fmt.Errorf("dial AWS proxy: %w", err)
			}
			return conn, nil
		},
		ResponseHeaderTimeout: 5 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxConnsPerHost:       32,
	}}
}

// Close releases idle proxy connections.
func (f *Forwarder) Close() { f.transport.CloseIdleConnections() }

// Handler is called by a surface after its signature and IAM checks.
func (f *Forwarder) Handler(service sigv4.Service, writeError func(http.ResponseWriter, *http.Request, error),
) func(http.ResponseWriter, *http.Request, resource.Caller, string) {
	return func(w http.ResponseWriter, r *http.Request, caller resource.Caller, action string) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		requestID := obs.RequestID(ctx)
		start, status := time.Now(), http.StatusServiceUnavailable
		defer func() { f.record(ctx, w, r, caller, service, action, status, start) }()
		body, err := r.GetBody()
		if err != nil {
			writeError(w, r, resource.Internal(fmt.Errorf("replay verified body: %w", err)))
			return
		}
		r = r.Clone(ctx)
		r.Body = body
		p := &httputil.ReverseProxy{
			Transport: otelhttp.NewTransport(f.transport),
			ModifyResponse: func(resp *http.Response) error {
				status = resp.StatusCode
				return nil
			},
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme, pr.Out.URL.Host = "http", "proxy"
				pr.Out.Host = "proxy"
				for name := range pr.Out.Header {
					if strings.HasPrefix(strings.ToLower(name), "x-vws-") {
						pr.Out.Header.Del(name)
					}
				}
				pr.Out.Header.Del("Authorization")
				pr.Out.Header.Del("X-Amz-Security-Token")
				pr.Out.Header.Set("X-Vws-Account", caller.Account.String())
				pr.Out.Header.Set("X-Vws-Principal", caller.Principal)
				pr.Out.Header.Set("X-Vws-Target-Region", caller.Region)
				pr.Out.Header.Set("X-Vws-Target-Service", string(service))
				pr.Out.Header.Set("X-Vws-Request-Id", requestID)
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, _ error) {
				writeError(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "AWS proxy unavailable"})
			},
		}
		p.ServeHTTP(w, r)
	}
}

// record audits a forwarded change request; reads are not audited.
func (f *Forwarder) record(
	ctx context.Context, w http.ResponseWriter, r *http.Request, caller resource.Caller,
	service sigv4.Service, action string, status int, start time.Time,
) {
	get := r.Method == http.MethodGet || r.Method == http.MethodHead
	read := service == sigv4.ServiceEC2 && strings.HasPrefix(action, "Describe") || service != sigv4.ServiceEC2 && get
	if f.audit == nil || read {
		return
	}
	result := audit.Accepted
	if status == http.StatusForbidden || status == http.StatusUnauthorized {
		result = audit.Denied
	} else if status >= 400 {
		result = audit.Error(strconv.Itoa(status))
	}
	entry := audit.Entry{
		RequestID: obs.RequestID(ctx), PrincipalARN: caller.Principal, Account: caller.Account.String(),
		Region: caller.Region, Destination: audit.AWS, Service: string(service), Action: action,
		Result: result, SourceIP: caller.SourceIP, Latency: time.Since(start),
	}
	if span := trace.SpanContextFromContext(ctx); span.IsValid() {
		entry.TraceID = span.TraceID().String()
	}
	if err := f.audit.Record(ctx, entry); err != nil {
		server.RecordFailure(w, report.Error(ctx, err))
	}
}

// ForwardConfig checks requests for any AWS service before Any forwards them.
type ForwardConfig struct {
	Verifier   func(sigv4.Service) *sigv4.Verifier
	Authorizer iam.Authorizer
	Error      func(http.ResponseWriter, *http.Request, error)
}

// Any verifies the signature for the credential scope's service, authorizes
// every action Action derives on "*", and forwards the verified bytes unchanged.
func (f *Forwarder) Any(cfg ForwardConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, service, err := sigv4.CredentialScope(r.Header.Get("Authorization"))
		if err != nil {
			cfg.Error(w, r, err)
			return
		}
		caller, err := cfg.Verifier(service).Verify(r)
		if err != nil {
			cfg.Error(w, r, err)
			return
		}
		actions, err := Action(service, r)
		if err == nil && len(actions) == 0 {
			err = resource.Invalid("Action", "cannot be derived")
		}
		if err != nil {
			cfg.Error(w, r, err)
			return
		}
		op := strings.TrimPrefix(actions[0], string(service)+":")
		for _, action := range actions {
			if err := iam.Check(r.Context(), cfg.Authorizer, caller, action, "*"); err != nil {
				f.record(r.Context(), w, r, caller, service, op, http.StatusForbidden, time.Now())
				cfg.Error(w, r, err)
				return
			}
		}
		f.Handler(service, cfg.Error)(w, r, caller, op)
	})
}
