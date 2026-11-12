package regionapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// OpenConsole returns a region-owned session; no PVE address or credential crosses the wire.
func (c *Client) OpenConsole(
	ctx context.Context, scope backend.Scope, id resource.InstanceID, kind resource.ConsoleKind,
) (resource.ConsoleSession, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var result consoleResult
	if err := c.Call(ctx, "Console", "OpenConsole", scope, consoleRequest{ID: id, Kind: kind}, &result); err != nil {
		return resource.ConsoleSession{}, err
	}
	if result.Token == "" || result.Session.Kind != kind || result.Session.Expires.IsZero() {
		return resource.ConsoleSession{}, resource.Internal(errors.New("invalid console response"))
	}
	path := "/internal/v1/console/" + id.String() + "?kind=" + kind.String()
	session := result.Session
	session.URL = "wss" + strings.TrimPrefix(c.base, "https") + path
	target := session.URL
	session.Dial = func(ctx context.Context) (resource.ConsoleStream, error) {
		transport, ok := c.http.Transport.(*http.Transport)
		if !ok {
			return nil, resource.Internal(errors.New("invalid region transport"))
		}
		dialer := websocket.Dialer{
			TLSClientConfig: transport.TLSClientConfig, HandshakeTimeout: 10 * time.Second,
		}
		conn, response, err := dialer.DialContext(ctx, target, http.Header{"X-Vws-Console-Session": {result.Token}})
		if response != nil {
			err = errors.Join(err, response.Body.Close())
		}
		if err != nil {
			if conn != nil {
				closeConsole(ctx, conn)
			}
			return nil, &resource.Error{Code: resource.CodeUnavailable, Message: "console unavailable"}
		}
		conn.SetReadLimit(4 << 20)
		return conn, nil
	}
	return session, nil
}
