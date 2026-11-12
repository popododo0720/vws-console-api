package regionapi

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/consolestream"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type consoleRequest struct {
	ID   resource.InstanceID  `json:"id"`
	Kind resource.ConsoleKind `json:"kind"`
}

type consoleResult struct {
	Session resource.ConsoleSession `json:"session"`
	Token   string                  `json:"token"`
}

type pendingConsole struct {
	session resource.ConsoleSession
	id      resource.InstanceID
}

func registerConsole(mux *http.ServeMux, cfg Config) {
	console, now := cfg.Backend.Console, cfg.ConsoleNow
	if now == nil {
		now = time.Now
	}
	var mu sync.Mutex
	opening := 0
	sessions := map[string]pendingConsole{}
	register(mux, cfg, "Console", "OpenConsole", func(
		ctx context.Context, scope backend.Scope, req consoleRequest,
	) (consoleResult, error) {
		if req.ID.IsZero() || (req.Kind != resource.ConsoleVNC && req.Kind != resource.ConsoleSerial) {
			return consoleResult{}, resource.Invalid("console", "instance and vnc or serial kind are required")
		}
		if console == nil {
			return consoleResult{}, resource.Unsupported("OpenConsole", "console unavailable")
		}
		mu.Lock()
		for token, s := range sessions {
			if !now().Before(s.session.Expires) {
				delete(sessions, token)
			}
		}
		if len(sessions)+opening >= 1024 {
			mu.Unlock()
			return consoleResult{}, &resource.Error{Code: resource.CodeResourceExhausted, Message: "console session limit"}
		}
		opening++
		mu.Unlock()
		defer func() {
			mu.Lock()
			opening--
			mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		session, err := console.OpenConsole(ctx, scope, req.ID, req.Kind)
		if err != nil {
			return consoleResult{}, err
		}
		if session.Dial == nil {
			return consoleResult{}, resource.Unsupported("OpenConsole", "console transport unavailable")
		}
		mu.Lock()
		defer mu.Unlock()
		if limit := now().Add(5 * time.Minute); limit.Before(session.Expires) {
			session.Expires = limit
		}
		token := rand.Text()
		if _, exists := sessions[token]; exists {
			return consoleResult{}, &resource.Error{Code: resource.CodeUnavailable, Message: "console session unavailable"}
		}
		sessions[token] = pendingConsole{session: session, id: req.ID}
		return consoleResult{Session: session, Token: token}, nil
	})
	mux.HandleFunc("GET /internal/v1/console/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		q, parseErr := url.ParseQuery(r.URL.RawQuery)
		kind := q.Get("kind")
		if parseErr != nil || len(q) != 1 || len(q["kind"]) != 1 || (kind != "vnc" && kind != "serial") ||
			!websocket.IsWebSocketUpgrade(r) || r.Header.Get("Origin") != "" {
			writeJSON(w, nil, resource.Invalid("console", "expected an internal websocket request with one kind"))
			return
		}
		mu.Lock()
		token := r.Header.Get("X-Vws-Console-Session")
		pending, ok := sessions[token]
		session := pending.session
		if ok && session.Kind.String() == kind && pending.id.String() == r.PathValue("id") {
			delete(sessions, token)
		} else {
			ok = false
		}
		valid := ok && now().Before(session.Expires)
		mu.Unlock()
		if !valid {
			writeJSON(w, nil, resource.Denied("console session expired or already used"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Hour)
		defer cancel()
		upstream, dialErr := session.Dial(ctx)
		if dialErr != nil {
			writeJSON(w, nil, &resource.Error{Code: resource.CodeUnavailable, Message: "console unavailable"})
			return
		}
		defer consolestream.Close(ctx, upstream)
		upgrader := websocket.Upgrader{HandshakeTimeout: 10 * time.Second}
		downstream, upgradeErr := upgrader.Upgrade(w, r, nil)
		if upgradeErr != nil {
			return
		}
		defer consolestream.Close(ctx, downstream)
		downstream.SetReadLimit(4 << 20)
		consolestream.Relay(ctx, upstream, downstream)
	})
}
