package regionapi

//vws:unseeded websocket handshakes use crypto/rand concurrently with the TLS server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type consoleFunc func(context.Context, backend.Scope, resource.InstanceID, resource.ConsoleKind) (
	resource.ConsoleSession, error,
)

func (f consoleFunc) OpenConsole(
	ctx context.Context, s backend.Scope, id resource.InstanceID, k resource.ConsoleKind,
) (resource.ConsoleSession, error) {
	return f(ctx, s, id, k)
}

func TestConsoleRelayExpiryReuseAndRestart(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			kind, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(kind, data); err != nil {
				return
			}
		}
	}))
	defer upstream.Close()
	var clock atomic.Int64
	clock.Store(1_700_000_000_000_000_000)
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	var dials atomic.Int32
	scope := testScope(t)
	id, _ := resource.Parse[resource.InstanceID]("i-0123456789abcdef0")
	set := fake.New(fake.Options{}).Set()
	set.Console = consoleFunc(func(
		_ context.Context, got backend.Scope, gotID resource.InstanceID, kind resource.ConsoleKind,
	) (resource.ConsoleSession, error) {
		if got != scope || gotID != id {
			t.Errorf("scope or instance changed: %+v %v", got, gotID)
		}
		return resource.ConsoleSession{
			Kind: kind, Expires: now().Add(time.Hour),
			Dial: func(ctx context.Context) (resource.ConsoleStream, error) {
				dials.Add(1)
				conn, resp, err := websocket.DefaultDialer.DialContext(ctx, "ws"+strings.TrimPrefix(upstream.URL, "http"), nil)
				if resp != nil {
					resp.Body.Close()
				}
				return conn, err
			},
		}, nil
	})
	cfg := config(set)
	cfg.ConsoleNow = now
	client, _ := loopback(t, cfg)
	remote, err := regionclient.New(client)
	if err != nil || remote.Console == nil {
		t.Fatalf("console adapter: %v", err)
	}
	for _, kind := range []resource.ConsoleKind{resource.ConsoleVNC, resource.ConsoleSerial} {
		session, err := remote.Console.OpenConsole(t.Context(), scope, id, kind)
		if err != nil || !session.Expires.Equal(now().Add(5*time.Minute)) {
			t.Fatalf("session: %+v %v", session, err)
		}
		var wg sync.WaitGroup
		var opened atomic.Int32
		for range 2 {
			wg.Go(func() {
				conn, err := session.Dial(t.Context())
				if err != nil {
					return
				}
				opened.Add(1)
				defer conn.Close()
				for _, typ := range []int{websocket.BinaryMessage, websocket.TextMessage} {
					writer, err := conn.NextWriter(typ)
					if err != nil {
						t.Error(err)
						return
					}
					io.WriteString(writer, "console bytes")
					writer.Close()
					gotType, reader, err := conn.NextReader()
					if err != nil {
						t.Error(err)
						return
					}
					data, err := io.ReadAll(reader)
					if err != nil || gotType != typ || string(data) != "console bytes" {
						t.Errorf("relay changed frame: %d %q %v", gotType, data, err)
					}
				}
			})
		}
		wg.Wait()
		if opened.Load() != 1 {
			t.Fatalf("concurrent opens: %d", opened.Load())
		}
	}
	for _, age := range []time.Duration{5 * time.Minute, 5*time.Minute + time.Second} {
		session, err := remote.Console.OpenConsole(t.Context(), scope, id, resource.ConsoleVNC)
		if err != nil {
			t.Fatal(err)
		}
		before := dials.Load()
		clock.Add(int64(age))
		if conn, err := session.Dial(t.Context()); err == nil {
			conn.Close()
			t.Fatal("expired session opened")
		}
		if dials.Load() != before {
			t.Fatal("expired session reached backend")
		}
	}
	var pending consoleResult
	err = client.Call(t.Context(), "Console", "OpenConsole", scope,
		consoleRequest{ID: id, Kind: resource.ConsoleVNC}, &pending)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"kind=vnc&kind=serial", "kind=vnc&extra=1", "kind=bad", "kind=vnc;bad"} {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/internal/v1/console/unknown?"+query, nil)
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
		h, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, request)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("query %q: %d", query, rec.Code)
		}
	}
	fresh, freshServer := loopback(t, cfg)
	target := "wss" + strings.TrimPrefix(freshServer.URL, "https") + "/internal/v1/console/" + id.String() + "?kind=vnc"
	dialer := websocket.Dialer{TLSClientConfig: fresh.http.Transport.(*http.Transport).TLSClientConfig}
	conn, resp, err := dialer.DialContext(t.Context(), target, http.Header{"X-Vws-Console-Session": {pending.Token}})
	if resp != nil {
		defer resp.Body.Close()
	}
	if err == nil {
		conn.Close()
		t.Fatal("restart preserved session")
	}
	if resp == nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("restart did not refuse handle: %v", err)
	}
}
