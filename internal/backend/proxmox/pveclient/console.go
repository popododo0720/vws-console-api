package pveclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
)

// Console opens a ticket and returns a dial capability confined to this client.
func (c *Client) Console(
	ctx context.Context, vm VM, serial bool,
) (func(context.Context) (*websocket.Conn, error), error) {
	node, err := segment("node", vm.Node)
	if err != nil {
		return nil, err
	}
	if vm.VMID < 100 || vm.VMID > 999999999 {
		return nil, errors.New("pve console: invalid VM ID")
	}
	transport, ok := c.http.Transport.(*http.Transport)
	if c.http.Transport == nil {
		transport, ok = http.DefaultTransport.(*http.Transport)
	}
	if !ok {
		return nil, errors.New("pve console: HTTP transport required")
	}
	u := *c.base
	path := strings.TrimSuffix(u.Path, "/") + "/api2/json/nodes" + node + "/qemu/" + strconv.Itoa(vm.VMID)
	endpoint, form := "vncproxy", "websocket=1"
	if serial {
		endpoint, form = "termproxy", "serial=serial0"
	}
	u.Path = path + "/" + endpoint
	ctx, cancel := context.WithTimeout(ctx, ReadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form))
	if err != nil {
		return nil, errors.New("pve console: invalid request")
	}
	req.Header.Set("Authorization", string(c.auth))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("pve console: proxy unavailable")
	}
	var answer struct {
		Data struct {
			Port   json.Number `json:"port"`
			Ticket string      `json:"ticket"`
		} `json:"data"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&answer)
	err = errors.Join(err, resp.Body.Close())
	port, portErr := answer.Data.Port.Int64()
	if err != nil || portErr != nil || resp.StatusCode != http.StatusOK || port < 1 ||
		port > 65535 || answer.Data.Ticket == "" {
		return nil, errors.New("pve console: proxy refused")
	}
	u.Path = path + "/vncwebsocket"
	u.RawQuery = url.Values{
		"port": {strconv.FormatInt(port, 10)}, "vncticket": {answer.Data.Ticket},
	}.Encode()
	u.Scheme = map[string]string{"http": "ws", "https": "wss"}[u.Scheme]
	dialer := websocket.Dialer{
		NetDialContext: transport.DialContext, TLSClientConfig: transport.TLSClientConfig,
		Proxy: transport.Proxy, HandshakeTimeout: ReadTimeout,
	}
	return func(ctx context.Context) (*websocket.Conn, error) {
		conn, response, err := dialer.DialContext(ctx, u.String(), http.Header{"Authorization": {string(c.auth)}})
		if response != nil {
			err = errors.Join(err, response.Body.Close())
		}
		if err != nil {
			if conn != nil {
				if closeErr := conn.Close(); closeErr != nil {
					return nil, errors.New("pve console: websocket close failed")
				}
			}
			return nil, errors.New("pve console: websocket unavailable")
		}
		conn.SetReadLimit(4 << 20)
		return conn, nil
	}, nil
}
