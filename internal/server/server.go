// Package server runs one listener per surface. The process stays stateless:
// shutting down drops no records, because the records live in the backends.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Surface is one protocol on its own address.
type Surface struct {
	Name    string
	Addr    string
	Handler http.Handler
}

// Run serves surfaces until ctx is cancelled or a listener fails.
// It then shuts the listeners down. In-flight requests get five seconds.
func Run(ctx context.Context, logger *slog.Logger, surfaces ...Surface) error {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	servers := make([]*http.Server, 0, len(surfaces))
	errc := make(chan error, len(surfaces))
	var wg sync.WaitGroup
	for _, sf := range surfaces {
		srv := newHTTPServer(sf.Addr, wrap(logger, sf.Name, sf.Handler))
		servers = append(servers, srv)
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errc <- fmt.Errorf("%s: %w", name, err)
			}
		}(sf.Name)
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutCtx)
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
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.ErrorContext(r.Context(), "panic", "surface", name, "requestId", id, "panic", recovered)
				http.Error(rec, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(rec, r)
		logger.InfoContext(r.Context(), "request", "surface", name, "requestId", id, "method", r.Method, "path", r.URL.Path, "status", rec.status)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
