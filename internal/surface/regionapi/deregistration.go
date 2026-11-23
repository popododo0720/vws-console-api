package regionapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/popododo0720/vws-lib/obs/httpobs"
	"github.com/popododo0720/vws-lib/obs/report"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
)

const (
	deregisterPath     = "/internal/v1/deregister"
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
