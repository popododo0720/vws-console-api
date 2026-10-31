// Package server runs one listener per surface. The process stays stateless:
// shutting down drops no records, because the records live in the backends.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/popododo0720/vws-lib/obs"
	"github.com/popododo0720/vws-lib/obs/httpobs"
	"github.com/popododo0720/vws-lib/obs/report"

	"github.com/popododo0720/vws-console-api/internal/service"
)

// Surface is one protocol on its own address.
type Surface struct {
	Name    string
	Addr    string
	Handler http.Handler
}

// Options configures Serve.
type Options struct {
	Logger   *slog.Logger
	Surfaces []Surface
	// OpsAddr, when set, serves /healthz, /readyz, and /metrics on its own
	// listener. /readyz is 200 while the surfaces serve and 503 once
	// shutdown starts.
	OpsAddr string
}

// Serve serves surfaces, plus an optional operations listener, until ctx is
// cancelled or a listener fails. It then shuts the listeners down. In-flight
// requests get five seconds. A stop the caller asked for returns nil even when
// that bound expires: the remaining connections are closed and the expiry is
// logged.
func Serve(ctx context.Context, opts Options) error {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	metrics := NewMetrics()
	var ready atomic.Bool
	type listener struct {
		name    string
		handler http.Handler
		addr    string
	}
	listeners := make([]listener, 0, len(opts.Surfaces)+1)
	for _, sf := range opts.Surfaces {
		listeners = append(listeners, listener{sf.Name, surfaceHandler(logger, metrics, sf), sf.Addr})
	}
	if opts.OpsAddr != "" {
		listeners = append(listeners, listener{"ops", opsHandler(metrics, &ready), opts.OpsAddr})
	}
	servers := make([]*http.Server, 0, len(listeners))
	errc := make(chan error, len(listeners))
	var wg sync.WaitGroup
	for _, l := range listeners {
		srv := newHTTPServer(l.addr, l.handler)
		servers = append(servers, srv)
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", name, err)
			}
		}(l.name)
	}
	ready.Store(true)

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	ready.Store(false)
	shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		// Shutdown closes idle connections and waits for in-flight requests
		// until shutCtx expires. A connection that accepted but never sent a
		// request stays in StateNew for its whole five second window
		// (https://go.dev/issue/22682), so the bound can expire with no request
		// in flight. The caller asked to stop, so report the stop as clean and
		// close what remains; a listener failure is already in runErr.
		if err := srv.Shutdown(shutCtx); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				logger.WarnContext(context.WithoutCancel(ctx), "shutdown drain bound expired", slog.Any("err", err))
			} else {
				runErr = errors.Join(runErr, err)
			}
			if cerr := srv.Close(); cerr != nil {
				runErr = errors.Join(runErr, cerr)
			}
		}
	}
	wg.Wait()
	return runErr
}

// surfaceHandler is the chain every surface request runs through: the
// per-surface counters, the inbound header guard, the OpenTelemetry server
// span and vws.http.server.* metrics, then the request id, access log, and
// panic recovery.
func surfaceHandler(logger *slog.Logger, metrics *Metrics, sf Surface) http.Handler {
	handler := httpobs.Middleware(service.Name, routePattern(sf.Handler))(wrap(logger, sf.Name, sf.Handler))
	return instrument(metrics, sf.Name, sanitizeInbound(handler))
}

const maxRequestIDBytes = 64

// sanitizeInbound drops an inbound request id that is too long or carries a
// byte outside the safe set, and drops an inbound traceparent and tracestate,
// before httpobs.Middleware reads them. Unbounded or unsafe text would
// otherwise reach the response header, the EC2, S3 and IAM RequestId, and the
// logs, and a caller-chosen traceparent would let the caller force sampling.
func sanitizeInbound(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !safeRequestID(r.Header.Get(httpobs.RequestIDHeader)) {
			r.Header.Del(httpobs.RequestIDHeader)
		}
		r.Header.Del("traceparent")
		r.Header.Del("tracestate")
		next.ServeHTTP(w, r)
	})
}

// safeRequestID reports whether id is non-empty and at most
// maxRequestIDBytes of [A-Za-z0-9._:-].
func safeRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDBytes {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		case c == '.', c == '_', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func wrap(logger *slog.Logger, name string, next http.Handler) http.Handler {
	route := routePattern(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := obs.RequestID(r.Context())
		if id == "" {
			id = obs.NewRequestID()
			r = r.WithContext(obs.WithRequestID(r.Context(), id))
		}
		r.Header.Set(httpobs.RequestIDHeader, id)
		w.Header().Set(httpobs.RequestIDHeader, id)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer recoverPanic(rec, r)
		next.ServeHTTP(rec, r)
		attrs := []slog.Attr{
			slog.String("surface", name),
			slog.String("method", r.Method),
			slog.String("path", route(r)),
			slog.Int("status", rec.status),
		}
		switch {
		case rec.status >= http.StatusInternalServerError:
			if rec.failure != nil {
				attrs = append(attrs, slog.Any("err", rec.failure))
			}
			logger.LogAttrs(r.Context(), slog.LevelError, "request failed", attrs...)
		case rec.failure != nil:
			logger.LogAttrs(r.Context(), slog.LevelWarn, "response failed", append(attrs, slog.Any("err", rec.failure))...)
		}
		logger.LogAttrs(r.Context(), slog.LevelInfo, "request", attrs...)
	})
}

// routePattern is the handler's route template, never the raw path. A
// console handler names its mux pattern; every other surface answers "/",
// because its action is in the body or its bucket and key must not become a
// log field or a metric label.
func routePattern(h http.Handler) func(*http.Request) string {
	return func(r *http.Request) string {
		if p, ok := h.(interface{ RoutePattern(*http.Request) string }); ok {
			if pattern := p.RoutePattern(r); pattern != "" {
				return pattern
			}
		}
		return "/"
	}
}

// recoverPanic turns a handler panic into a bare 500. report.Panic records it
// once and returns the Internal error the client would see; the panic value
// stays out of the response.
func recoverPanic(w http.ResponseWriter, r *http.Request) {
	recovered := recover()
	if recovered == nil {
		return
	}
	report.Panic(r.Context(), recovered) //nolint:errcheck // the client gets a fixed 500, not the error
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// RecordFailure keeps err for the access log. Surfaces call it when the
// response is a server error. The cause stays off the wire body.
// A failure under a 2xx or 4xx status is logged as a warning.
func RecordFailure(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	if n, ok := w.(interface{ noteFailure(error) }); ok {
		n.noteFailure(err)
	}
}

// Close closes c and records its error for the access log.
func Close(w http.ResponseWriter, c io.Closer) {
	RecordFailure(w, c.Close())
}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	failure error
}

func (s *statusRecorder) noteFailure(err error) { s.failure = errors.Join(s.failure, err) }

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
