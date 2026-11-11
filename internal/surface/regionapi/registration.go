package regionapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/popododo0720/vws-lib/obs/httpobs"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// WithRegistration exposes registration before a region backend is ready.
// The returned handler belongs exclusively on the mutual TLS server.
func WithRegistration(register func(context.Context, json.RawMessage) error, next http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", next)
	mux.Handle("PUT /internal/v1/registration", httpobs.Middleware("regionapi", nil)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
			if err == nil {
				err = register(r.Context(), data)
			}
			if err == nil {
				writeJSON(w, struct{}{}, nil)
				return
			}
			if e := resource.AsError(err); e.Code == resource.CodeInvalidArgument && e.Field == "token" {
				writeJSON(w, nil, resource.Invalid("token", "token required or stored token invalid"))
				return
			}
			status, message := http.StatusBadRequest, "invalid registration"
			var tooLarge *http.MaxBytesError
			switch {
			case errors.As(err, &tooLarge):
				status, message = http.StatusRequestEntityTooLarge, "registration exceeds 64 KiB"
			case resource.AsError(err).Code == resource.CodeConflict:
				status, message = http.StatusConflict, "registration conflict"
			case resource.AsError(err).Code != resource.CodeInvalidArgument:
				status, message = http.StatusServiceUnavailable, "registration failed"
			}
			http.Error(w, message, status)
		})))
	return mux
}
