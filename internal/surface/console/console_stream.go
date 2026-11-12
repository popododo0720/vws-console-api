package console

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"

	"github.com/popododo0720/vws-console-api/internal/consolestream"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const routeConsole = "GET /api/v1/instances/{id}/console"

func (h *handler) openConsole(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q, err := url.ParseQuery(r.URL.RawQuery)
	kind := resource.ConsoleVNC
	if q.Get("kind") == "serial" {
		kind = resource.ConsoleSerial
	}
	if err != nil || len(q) != 1 || len(q["kind"]) != 1 ||
		(q.Get("kind") != "vnc" && q.Get("kind") != "serial") || !websocket.IsWebSocketUpgrade(r) {
		writeErr(w, r, resource.Invalid("console", "expected a websocket request with one vnc or serial kind"))
		return
	}
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	id, err := resource.Parse[resource.InstanceID](r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	session, err := h.svc.OpenConsole(r.Context(), c, id, kind)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Hour)
	defer cancel()
	upstream, err := session.Dial(ctx)
	if err != nil {
		writeErr(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "console unavailable"})
		return
	}
	defer consolestream.Close(ctx, upstream)
	upgrader := websocket.Upgrader{
		HandshakeTimeout: 10 * time.Second,
		CheckOrigin:      func(r *http.Request) bool { return h.originOK(r.Header.Get("Origin"), r.Host) },
	}
	downstream, err := upgrader.Upgrade(w, r, w.Header())
	if err != nil {
		return
	}
	defer consolestream.Close(ctx, downstream)
	downstream.SetReadLimit(4 << 20)
	consolestream.Relay(ctx, upstream, downstream)
}
