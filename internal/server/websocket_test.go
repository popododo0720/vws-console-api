package server

//vws:unseeded websocket handshakes use crypto/rand concurrently with the server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type consoleWebsocketHandler struct{ http.Handler }

func (consoleWebsocketHandler) RoutePattern(*http.Request) string {
	return "GET /api/v1/instances/{id}/console"
}

func TestWebsocketSurfaceUpgrade(t *testing.T) {
	for _, surface := range []string{"console", "ec2", "s3"} {
		t.Run(surface, func(t *testing.T) {
			testWebsocketSurface(t, surface)
		})
	}
}

func testWebsocketSurface(t *testing.T, surface string) {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, w.Header())
		if err != nil {
			return
		}
		defer conn.Close()
		if err := conn.WriteMessage(websocket.BinaryMessage, []byte("RFB 003.008\n")); err != nil {
			t.Error(err)
		}
	})
	metrics := NewMetrics()
	wrapped := surfaceHandler(slog.New(slog.DiscardHandler), metrics,
		Surface{Name: surface, Handler: consoleWebsocketHandler{handler}})
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		wrapped.ServeHTTP(w, r)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, resp, err := websocket.DefaultDialer.DialContext(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"),
		http.Header{"X-Request-Id": {"console-websocket"}})
	if resp != nil {
		defer resp.Body.Close()
		if resp.Header.Get("X-Request-Id") != "console-websocket" {
			t.Fatal("websocket headers lost the validated client request id")
		}
	}
	if surface != "console" {
		if err == nil {
			conn.Close()
			t.Fatal("non-console request bypassed normal HTTP telemetry")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil || string(data) != "RFB 003.008\n" {
		t.Fatalf("middleware console stream: %q %v", data, err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("middleware did not finish")
	}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if metrics.requests[requestKey{surface: "console", code: http.StatusSwitchingProtocols}] != 1 {
		t.Fatal("websocket upgrade was not counted as 101")
	}
}
