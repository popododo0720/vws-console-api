// Package regionapi transports the region backend after the global kernel.
package regionapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/popododo0720/vws-lib/obs/httpobs"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
)

const maxRequestBytes = 1 << 20

// Version identifies the release compatibility line and registered cluster.
type Version struct {
	ReleaseLine string `json:"releaseLine"`
	//nolint:tagliatelle // The region handshake names cluster_name.
	ClusterName string `json:"cluster_name"`
}

// Config supplies the backend and handshake identity of one region.
type Config struct {
	Backend      backend.Set
	Capabilities backend.Capabilities
	Region       string
	Version      Version
}

// ObjectResult keeps the object metadata and bytes together on the JSON wire.
type ObjectResult struct {
	Object resource.Object `json:"object"`
	Body   []byte          `json:"body"`
}

type errorBody struct {
	Error *resource.Error `json:"error"`
}

// New returns the region's read-only HTTP handler.
func New(cfg Config) (http.Handler, error) {
	if cfg.Backend.Compute == nil || cfg.Backend.Storage == nil || cfg.Backend.Network == nil {
		return nil, fmt.Errorf("new region API: compute, storage and network backends are required")
	}
	if cfg.Capabilities == nil || cfg.Region == "" {
		return nil, fmt.Errorf("new region API: capabilities and region are required")
	}
	if cfg.Version.ReleaseLine == "" || cfg.Version.ClusterName == "" {
		return nil, fmt.Errorf("new region API: release line and cluster name are required")
	}
	mux := http.NewServeMux()
	c, s, n := cfg.Backend.Compute, cfg.Backend.Storage, cfg.Backend.Network
	register(mux, "Compute", "DescribeInstances", c.DescribeInstances)
	register(mux, "Compute", "DescribeVolumes", c.DescribeVolumes)
	register(mux, "Compute", "DescribeImages", c.DescribeImages)
	register(mux, "Compute", "DescribeKeyPairs", c.DescribeKeyPairs)
	register(mux, "Compute", "DescribeSnapshots", c.DescribeSnapshots)
	register(mux, "Compute", "GetOperation", c.GetOperation)
	register(mux, "Network", "DescribeSubnets", n.DescribeSubnets)
	register(mux, "Network", "DescribeVpcs", n.DescribeVpcs)
	register(mux, "Network", "DescribeSecurityGroups", n.DescribeSecurityGroups)
	register(mux, "Network", "DescribeAddresses", n.DescribeAddresses)
	register(mux, "Network", "GetOperation", n.GetOperation)
	register(mux, "Storage", "GetBucket", s.GetBucket)
	register(mux, "Storage", "ListBuckets", s.ListBuckets)
	register(mux, "Storage", "ListObjects", s.ListObjects)
	register(mux, "Storage", "GetObject", func(ctx context.Context, scope backend.Scope,
		req resource.GetObjectRequest,
	) (ObjectResult, error) {
		obj, body, err := s.GetObject(ctx, scope, req)
		if err != nil {
			return ObjectResult{}, err
		}
		data, readErr := io.ReadAll(io.LimitReader(body, resource.MaxObjectBytes+1))
		closeErr := body.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return ObjectResult{}, resource.Internal(err)
		}
		if len(data) > resource.MaxObjectBytes {
			return ObjectResult{}, resource.TooLarge("object exceeds 4 MiB")
		}
		return ObjectResult{Object: obj, Body: data}, nil
	})
	mux.HandleFunc("GET /internal/v1/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, cfg.Version, nil)
	})
	mux.HandleFunc("GET /internal/v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		caps, err := cfg.Capabilities.RegionCapabilities(r.Context(), cfg.Region)
		writeJSON(w, caps, err)
	})
	return httpobs.Middleware("regionapi", nil)(mux), nil
}

func register[Q, R any](mux *http.ServeMux, iface, method string,
	call func(context.Context, backend.Scope, Q) (R, error),
) {
	mux.HandleFunc("POST /internal/v1/"+iface+"/"+method, func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Scope *backend.Scope `json:"scope"`
			Req   *Q             `json:"req"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
		dec.DisallowUnknownFields()
		err := dec.Decode(&input)
		if err == nil {
			var extra any
			if next := dec.Decode(&extra); next != io.EOF {
				err = resource.Invalid("body", "expected one JSON document")
			}
		}
		if err != nil || input.Scope == nil || input.Req == nil || input.Scope.Account.IsZero() {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				err = resource.TooLarge("body exceeds the limit")
			} else {
				err = resource.Invalid("body", "scope and req must be valid JSON")
			}
			writeJSON(w, nil, err)
			return
		}
		result, err := call(r.Context(), *input.Scope, *input.Req)
		writeJSON(w, result, err)
	})
}

func writeJSON(w http.ResponseWriter, value any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		e := resource.AsError(err)
		if e.Code == resource.CodeInternal {
			server.RecordFailure(w, err)
		}
		w.WriteHeader(http.StatusBadRequest)
		value = errorBody{Error: e}
	}
	server.RecordFailure(w, json.NewEncoder(w).Encode(value))
}

// Server exposes only TLS startup and bounded shutdown.
type Server struct{ http *http.Server }

// Serve accepts only TLS connections, requiring a verified client certificate.
func (s *Server) Serve(listener net.Listener) error {
	if err := s.http.ServeTLS(listener, "", ""); err != nil {
		return fmt.Errorf("serve region TLS: %w", err)
	}
	return nil
}

// ListenAndServe binds the configured address and serves only mutual TLS.
func (s *Server) ListenAndServe() error {
	if err := s.http.ListenAndServeTLS("", ""); err != nil {
		return fmt.Errorf("listen region TLS: %w", err)
	}
	return nil
}

// Shutdown drains the listener within the caller's deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.http.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown region TLS: %w", err)
	}
	return nil
}

// NewServer requires certificates from ca and bounds every listener timeout.
func NewServer(addr string, handler http.Handler, cert tls.Certificate, ca *x509.CertPool) *Server {
	return &Server{http: &http.Server{
		Addr: addr, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
			ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca,
		},
	}}
}
