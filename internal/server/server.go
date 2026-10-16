// Package server runs one listener per surface. The process stays stateless:
// shutting down drops no records, because the records live in the backends.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
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
// requests get five seconds.
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
		listeners = append(listeners, listener{sf.Name, instrument(metrics, sf.Name, wrap(logger, sf.Name, sf.Handler)), sf.Addr})
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
		runErr = errors.Join(runErr, srv.Shutdown(shutCtx))
	}
	wg.Wait()
	return runErr
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			var raw [8]byte
			_, _ = rand.Read(raw[:])
			id = hex.EncodeToString(raw[:])
			r.Header.Set("X-Request-Id", id)
		}
		w.Header().Set("X-Request-Id", id)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer recoverPanic(logger, rec, r, name, id)
		next.ServeHTTP(rec, r)
		attrs := []slog.Attr{
			slog.String("surface", name),
			slog.String("request_id", id),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
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
		logger.LogAttrs(r.Context(), slog.LevelInfo, "request", attrs[:5]...)
	})
}

// recoverPanic turns a handler panic into a bare 500. The panic value is
// logged and never written to the client.
func recoverPanic(logger *slog.Logger, w http.ResponseWriter, r *http.Request, name, id string) {
	recovered := recover()
	if recovered == nil {
		return
	}
	logger.LogAttrs(r.Context(), slog.LevelError, "panic",
		slog.String("surface", name),
		slog.String("request_id", id),
		slog.Any("panic", recovered))
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
