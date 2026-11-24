package regionapi

import (
	"bytes"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// An internal error keeps its cause off the wire but must reach the daemon log
// (vws-console-api#1078: a PVE decode error showed only as "internal error").
func TestNewServerLogsTheCauseOfAnInternalError(t *testing.T) {
	var log bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&log, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	cause := "pve GET /nodes/pve1/network: decode: json: cannot unmarshal string into Go struct field " +
		"NetworkInterface.data.active of type int"
	srv := NewServer("", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, nil, resource.Internal(errors.New(cause)))
	}), tls.Certificate{}, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/DescribeVpcs", nil)
	srv.http.Handler.ServeHTTP(rec, req)
	if body := rec.Body.String(); strings.Contains(body, "decode") || !strings.Contains(body, "internal error") {
		t.Fatalf("wire body: %s", body)
	}
	got := log.String()
	if !strings.Contains(got, `"surface":"region"`) || !strings.Contains(got, "NetworkInterface.data.active") {
		t.Fatalf("daemon log lacks the cause: %s", got)
	}
}
