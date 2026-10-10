package server

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestInternalErrorIsLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cause := errors.New(`bad operation name "projects/a/operations/op-zzzz"`)
	h := wrap(logger, "ec2", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		err := resource.Internal(cause)
		RecordFailure(w, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "bad operation name") {
		t.Fatalf("cause leaked: %s", rec.Body)
	}
	if !strings.Contains(buf.String(), "request failed") || !strings.Contains(buf.String(), "bad operation name") {
		t.Fatalf("log %s", buf.String())
	}
}

func TestListenerBounds(t *testing.T) {
	srv := newHTTPServer(":0", http.NewServeMux())
	if srv.ReadHeaderTimeout == 0 || srv.ReadTimeout == 0 || srv.WriteTimeout == 0 || srv.IdleTimeout == 0 {
		t.Fatalf("unbounded listener: header %s read %s write %s idle %s", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
}
