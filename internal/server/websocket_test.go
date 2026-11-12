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

func TestWebsocketSurfaceUpgrade(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if err := conn.WriteMessage(websocket.BinaryMessage, []byte("RFB 003.008\n")); err != nil {
			t.Error(err)
		}
	})
	metrics := NewMetrics()
	wrapped := surfaceHandler(slog.New(slog.DiscardHandler), metrics, Surface{Name: "console", Handler: handler})
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		wrapped.ServeHTTP(w, r)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, resp, err := websocket.DefaultDialer.DialContext(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if resp != nil {
		defer resp.Body.Close()
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
