package regionapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/popododo0720/vws-lib/obs/httpobs"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

const (
	connectionTestPath  = "/internal/v1/connection-test"
	maxConnectionBody   = 64 << 10
	maxConnectionTests  = 2
	connectionTestLimit = 12 * time.Second
)

// WithConnectionTest exposes the PVE connection test before a region backend
// is ready, so an operator can check a candidate registration first. Like
// registration it belongs only on the mutual TLS server: the caller is the
// global process, which holds a certificate from the global CA. At most
// maxConnectionTests run at once, so the route cannot be used to flood PVE
// addresses; the rest are refused with 503. The test keeps no state.
func WithConnectionTest(
	test func(context.Context, json.RawMessage) ([]resource.ConnectionStep, error), next http.Handler,
) http.Handler {
	slots := make(chan struct{}, maxConnectionTests)
	mux := http.NewServeMux()
	mux.Handle("/", next)
	instrumented := httpobs.Middleware("regionapi", func(*http.Request) string {
		return connectionTestPath
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			writeJSON(w, nil, &resource.Error{Code: resource.CodeUnavailable, Message: "connection test busy"})
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxConnectionBody))
		var steps []resource.ConnectionStep
		if err == nil {
			steps, err = test(r.Context(), data)
		}
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			err = resource.TooLarge("connection test exceeds 64 KiB")
		case err != nil && resource.AsError(err).Code != resource.CodeInvalidArgument:
			// Only validation text is safe to return; anything else is reported as fixed text.
			err = &resource.Error{Code: resource.CodeUnavailable, Message: "connection test failed"}
		}
		writeJSON(w, connectionResult{Steps: steps}, err)
	}))
	// One budget covers the upload and the test, so a stalled body cannot hold
	// a slot until the server's read timeout. The deadline is set here, outside
	// the instrumentation, whose writer does not unwrap to the connection.
	mux.Handle("POST "+connectionTestPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline := time.Now().Add(connectionTestLimit)
		if err := http.NewResponseController(w).SetReadDeadline(deadline); err != nil {
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, nil, &resource.Error{Code: resource.CodeUnavailable, Message: "connection test failed"})
			return
		}
		ctx, cancel := context.WithDeadline(r.Context(), deadline)
		defer cancel()
		instrumented.ServeHTTP(w, r.WithContext(ctx))
	}))
	return mux
}

type connectionResult struct {
	Steps []resource.ConnectionStep `json:"steps"`
}

// TestConnection asks the region daemon to run the PVE checks for the
// candidate registration in data, which carries a token secret. It returns
// only a result that passes resource.ValidPVEConnectionSteps.
func (c *Client) TestConnection(ctx context.Context, data json.RawMessage) ([]resource.ConnectionStep, error) {
	ctx, cancel := context.WithTimeout(ctx, connectionTestLimit+time.Second)
	defer cancel()
	var result connectionResult
	if err := c.do(ctx, http.MethodPost, connectionTestPath, data, &result); err != nil {
		return nil, err
	}
	if !resource.ValidPVEConnectionSteps(result.Steps) {
		return nil, &resource.Error{
			Code: resource.CodeUnavailable, Message: "region daemon returned an invalid connection test",
		}
	}
	return result.Steps, nil
}
