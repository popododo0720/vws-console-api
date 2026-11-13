// Package regionapi transports the region backend after the global kernel.
package regionapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/popododo0720/vws-lib/obs/httpobs"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
)

const maxRequestBytes = 1 << 20

func requestLimit(iface, method string) int {
	if iface == "Storage" && method == "PutObject" {
		// JSON base64 must carry the existing 4 MiB object contract.
		return maxRequestBytes + base64.StdEncoding.EncodedLen(resource.MaxObjectBytes)
	}
	return maxRequestBytes
}

// Gate admits a local mutation or names the peer holding the lease.
type Gate interface {
	Admit(context.Context) (string, error)
}

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
	Gate         Gate
	CheckScope   func(backend.Scope) error
	// ConsoleNow supplies the console admission clock. Nil uses time.Now.
	ConsoleNow func() time.Time
	Status     interface {
		Status(context.Context) (resource.RegionStatus, error)
	}
	Pools interface {
		PoolExists(context.Context, string) (bool, error)
	}
}

// ObjectResult keeps the object metadata and bytes together on the JSON wire.
type ObjectResult struct {
	Object resource.Object `json:"object"`
	Body   []byte          `json:"body"`
}

type errorBody struct {
	Error *resource.Error `json:"error"`
}

// New returns the region's backend HTTP handler.
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
	registerConsole(mux, cfg)
	c, s, n := cfg.Backend.Compute, cfg.Backend.Storage, cfg.Backend.Network
	if cfg.Backend.Usage != nil {
		register(mux, cfg, "Usage", "GetAllocation", cfg.Backend.Usage.GetAllocation)
	}
	register(mux, cfg, "Compute", "RunInstances", c.RunInstances)
	register(mux, cfg, "Compute", "StopInstances", c.StopInstances)
	register(mux, cfg, "Compute", "StartInstances", c.StartInstances)
	register(mux, cfg, "Compute", "TerminateInstances", c.TerminateInstances)
	register(mux, cfg, "Compute", "RebootInstances", c.RebootInstances)
	register(mux, cfg, "Compute", "CreateTags", c.CreateTags)
	register(mux, cfg, "Compute", "DeleteTags", c.DeleteTags)
	register(mux, cfg, "Compute", "CreateVolume", c.CreateVolume)
	register(mux, cfg, "Compute", "TagVolumes", c.TagVolumes)
	register(mux, cfg, "Compute", "UntagVolumes", c.UntagVolumes)
	register(mux, cfg, "Compute", "AttachVolume", c.AttachVolume)
	register(mux, cfg, "Compute", "DetachVolume", c.DetachVolume)
	register(mux, cfg, "Compute", "DeleteVolume", c.DeleteVolume)
	register(mux, cfg, "Compute", "ModifyVolume", c.ModifyVolume)
	register(mux, cfg, "Compute", "CreateKeyPair", c.CreateKeyPair)
	register(mux, cfg, "Compute", "DeleteKeyPair", c.DeleteKeyPair)
	register(mux, cfg, "Compute", "CreateSnapshot", c.CreateSnapshot)
	register(mux, cfg, "Compute", "DeleteSnapshot", c.DeleteSnapshot)
	register(mux, cfg, "Compute", "RegisterImage", c.RegisterImage)
	register(mux, cfg, "Network", "CreateSubnet", n.CreateSubnet)
	register(mux, cfg, "Network", "CreateVpc", n.CreateVpc)
	register(mux, cfg, "Network", "DeleteVpc", n.DeleteVpc)
	register(mux, cfg, "Network", "TagVpcs", n.TagVpcs)
	register(mux, cfg, "Network", "TagSubnets", n.TagSubnets)
	register(mux, cfg, "Network", "UntagVpcs", n.UntagVpcs)
	register(mux, cfg, "Network", "UntagSubnets", n.UntagSubnets)
	register(mux, cfg, "Network", "CreateSecurityGroup", n.CreateSecurityGroup)
	register(mux, cfg, "Network", "DeleteSecurityGroup", n.DeleteSecurityGroup)
	register(mux, cfg, "Network", "AuthorizeSecurityGroupIngress", n.AuthorizeSecurityGroupIngress)
	register(mux, cfg, "Network", "RevokeSecurityGroupIngress", n.RevokeSecurityGroupIngress)
	register(mux, cfg, "Network", "DeleteSubnet", n.DeleteSubnet)
	register(mux, cfg, "Network", "AllocateAddress", n.AllocateAddress)
	register(mux, cfg, "Network", "ReleaseAddress", n.ReleaseAddress)
	register(mux, cfg, "Network", "AssociateAddress", n.AssociateAddress)
	register(mux, cfg, "Network", "DisassociateAddress", n.DisassociateAddress)
	register(mux, cfg, "Compute", "DescribeInstances", c.DescribeInstances)
	register(mux, cfg, "Compute", "DescribeVolumes", c.DescribeVolumes)
	register(mux, cfg, "Compute", "DescribeImages", c.DescribeImages)
	register(mux, cfg, "Compute", "DescribeKeyPairs", c.DescribeKeyPairs)
	register(mux, cfg, "Compute", "DescribeSnapshots", c.DescribeSnapshots)
	register(mux, cfg, "Compute", "GetOperation", c.GetOperation)
	register(mux, cfg, "Network", "DescribeSubnets", n.DescribeSubnets)
	register(mux, cfg, "Network", "DescribeVpcs", n.DescribeVpcs)
	register(mux, cfg, "Network", "DescribeSecurityGroups", n.DescribeSecurityGroups)
	register(mux, cfg, "Network", "DescribeAddresses", n.DescribeAddresses)
	register(mux, cfg, "Network", "GetOperation", n.GetOperation)
	register(mux, cfg, "Storage", "GetBucket", s.GetBucket)
	register(mux, cfg, "Storage", "ListBuckets", s.ListBuckets)
	register(mux, cfg, "Storage", "ListObjects", s.ListObjects)
	register(mux, cfg, "Storage", "CreateBucket", s.CreateBucket, true)
	register(mux, cfg, "Storage", "DeleteBucket", func(ctx context.Context, scope backend.Scope,
		name resource.BucketName,
	) (struct{}, error) {
		return struct{}{}, s.DeleteBucket(ctx, scope, name)
	}, true)
	register(mux, cfg, "Storage", "DeleteObject", func(ctx context.Context, scope backend.Scope, req struct {
		Bucket resource.BucketName `json:"bucket"`
		Key    resource.ObjectKey  `json:"key"`
	},
	) (struct{}, error) {
		return struct{}{}, s.DeleteObject(ctx, scope, req.Bucket, req.Key)
	}, true)
	register(mux, cfg, "Storage", "PutObject", func(ctx context.Context, scope backend.Scope, req struct {
		Request resource.PutObjectRequest `json:"request"`
		Body    []byte                    `json:"body"`
	},
	) (resource.Object, error) {
		if len(req.Body) > resource.MaxObjectBytes {
			return resource.Object{}, resource.TooLarge("object exceeds 4 MiB")
		}
		return s.PutObject(ctx, scope, req.Request, bytes.NewReader(req.Body))
	}, true)
	register(mux, cfg, "Storage", "GetObject", func(ctx context.Context, scope backend.Scope,
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
	mux.HandleFunc("GET /internal/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if cfg.Status == nil {
			writeJSON(w, nil, &resource.Error{Code: resource.CodeUnavailable, Message: "region status unavailable"})
			return
		}
		status, err := cfg.Status.Status(r.Context())
		writeJSON(w, status, err)
	})
	mux.HandleFunc("GET /internal/v1/pools/{pool}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		pool := r.PathValue("pool")
		if err := checkPool(pool); err != nil {
			writeJSON(w, nil, err)
			return
		}
		if r.URL.RawQuery != "" {
			writeJSON(w, nil, resource.Invalid("query", "query parameters are not supported"))
			return
		}
		if cfg.Pools == nil {
			writeJSON(w, nil, &resource.Error{Code: resource.CodeUnavailable, Message: "region pools unavailable"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		exists, err := cfg.Pools.PoolExists(ctx, pool)
		writeJSON(w, poolResult{Exists: exists}, err)
	})
	mux.HandleFunc("GET /internal/v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		caps, err := cfg.Backend.Capabilities(cfg.Capabilities).RegionCapabilities(r.Context(), cfg.Region)
		writeJSON(w, caps, err)
	})
	handler := http.NewServeMux()
	// httpobs v0.1.1 hides Hijacker; otelhttp preserves it for streaming routes.
	handler.Handle("GET /internal/v1/console/{id}", otelhttp.NewHandler(mux, "regionapi.console"))
	handler.Handle("/", httpobs.Middleware("regionapi", nil)(mux))
	return handler, nil
}

func register[S backend.Scope | backend.Mutation, Q, R any](mux *http.ServeMux, cfg Config, iface, method string,
	call func(context.Context, S, Q) (R, error), writes ...bool,
) {
	mux.HandleFunc("POST /internal/v1/"+iface+"/"+method, func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Scope    *S `json:"scope"`
			Mutation *S `json:"mutation"`
			Req      *Q `json:"req"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, int64(requestLimit(iface, method))))
		dec.DisallowUnknownFields()
		err := dec.Decode(&input)
		if err == nil {
			var extra any
			if next := dec.Decode(&extra); next != io.EOF {
				err = resource.Invalid("body", "expected one JSON document")
			}
		}
		var scope backend.Scope
		mutation := len(writes) > 0 && writes[0]
		param := input.Scope
		if _, ok := any(*new(S)).(backend.Mutation); ok {
			param = input.Mutation
		}
		if param != nil && (input.Scope == nil || input.Mutation == nil) {
			switch value := any(*param).(type) {
			case backend.Scope:
				scope = value
			case backend.Mutation:
				scope, mutation = value.Scope, true
			}
		}
		if err != nil || param == nil || input.Req == nil || scope.Account.IsZero() {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				err = resource.TooLarge("body exceeds the limit")
			} else {
				err = resource.Invalid("body", "scope or mutation and req must be valid JSON")
			}
			writeJSON(w, nil, err)
			return
		}
		if cfg.CheckScope != nil {
			if err := cfg.CheckScope(scope); err != nil {
				writeJSON(w, nil, err)
				return
			}
		}
		if mutation && cfg.Gate != nil {
			peer, err := cfg.Gate.Admit(r.Context())
			if err != nil || peer != "" {
				writeJSON(w, nil, &resource.Error{Code: resource.CodeUnavailable, Message: "region leader unavailable"})
				return
			}
		}
		result, err := call(r.Context(), *param, *input.Req)
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
		status := http.StatusBadRequest
		if e.Code == resource.CodeUnavailable {
			status = http.StatusServiceUnavailable
		}
		w.WriteHeader(status)
		value = errorBody{Error: e}
	}
	server.RecordFailure(w, json.NewEncoder(w).Encode(encodeResult(value)))
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
