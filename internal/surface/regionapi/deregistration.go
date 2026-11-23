package regionapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/popododo0720/vws-lib/obs/httpobs"
	"github.com/popododo0720/vws-lib/obs/report"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
)

const (
	deregisterPath     = "/internal/v1/deregister"
	fencePath          = "/internal/v1/fence"
	maxDeregisterBytes = 4 << 10
)

// WithDeregistration exposes deregistration, which works with or without a
// registration. Like registration it belongs only on the mutual TLS server:
// the caller is the global process. deregister must remove the stored
// registration, stop everything that uses it and return only when that is
// done; it must succeed when nothing is registered. A failure is reported as
// fixed text, and the response never carries the request or a cause.
func WithDeregistration(deregister func(context.Context, json.RawMessage) error, next http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", next)
	// A daemon that serves this route also enforces registration generations.
	// An older one answers 404 or not ready, which is how a console tells them apart.
	mux.Handle("GET "+fencePath, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, struct {
			Generation bool `json:"generation"`
		}{true}, nil)
	}))
	mux.Handle("POST "+deregisterPath, httpobs.Middleware("regionapi", func(*http.Request) string {
		return deregisterPath
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDeregisterBytes))
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			big := errorBody{Error: resource.TooLarge("deregistration exceeds 4 KiB")}
			server.RecordFailure(w, json.NewEncoder(w).Encode(big))
			return
		}
		if err == nil {
			err = deregister(r.Context(), data)
		}
		if err != nil && !passesThrough(err) {
			err = report.Error(r.Context(), &resource.Error{Code: resource.CodeUnavailable, Message: "deregistration failed"},
				slog.String("op", "POST "+deregisterPath))
		}
		if err != nil && resource.AsError(err).Code == resource.CodeConflict {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			server.RecordFailure(w, json.NewEncoder(w).Encode(errorBody{Error: resource.AsError(err)}))
			return
		}
		writeJSON(w, struct{}{}, err)
	})))
	return mux
}

// Deregister asks the region daemon to delete its registration and become
// not ready and to refuse any registration older than generation. It is safe
// to repeat: a daemon with nothing registered succeeds.
func (c *Client) Deregister(ctx context.Context, region string, generation int64) error {
	data, err := json.Marshal(struct {
		Region     string `json:"region"`
		Generation int64  `json:"generation"`
	}{region, generation})
	if err != nil {
		return fmt.Errorf("encode deregistration: %w", err)
	}
	var result struct{}
	return c.do(ctx, http.MethodPost, deregisterPath, data, &result)
}

// passesThrough reports whether err is a refusal of the request itself, which
// is safe to return as is.
func passesThrough(err error) bool {
	code := resource.AsError(err).Code
	return code == resource.CodeInvalidArgument || code == resource.CodeConflict
}

// Fencing reports whether the daemon enforces registration generations and
// serves deregistration. An answer that is not the capability document, from a
// daemon that predates it, is false; only a failure to reach the daemon is an
// error.
func (c *Client) Fencing(ctx context.Context) (bool, error) {
	var result struct {
		Generation bool `json:"generation"`
	}
	err := c.do(ctx, http.MethodGet, fencePath, nil, &result)
	var transport *url.Error
	if errors.As(err, &transport) {
		return false, err
	}
	return err == nil && result.Generation, nil
}

// RegisterCompat forwards a registration. The generation field is sent only to
// a daemon that enforces it: an older daemon refuses unknown fields, and its
// registration must be applied, not refused. Without the capability the
// registration is applied unfenced.
func (c *Client) RegisterCompat(ctx context.Context, data json.RawMessage) error {
	fenced, err := c.Fencing(ctx)
	if err != nil {
		return err
	}
	if !fenced {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return resource.Invalid("registration", "invalid JSON")
		}
		delete(fields, "generation")
		if data, err = json.Marshal(fields); err != nil {
			return fmt.Errorf("encode registration: %w", err)
		}
	}
	return c.Register(ctx, data)
}
