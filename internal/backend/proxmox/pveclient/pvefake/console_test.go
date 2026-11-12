package pvefake_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
)

type consoleAnswer struct {
	Cert     string
	Port     int
	Ticket   string
	UPID     string
	User     string
	Password string
}

func consoleWorld(t *testing.T) (*taskWorld, *httptest.Server) {
	t.Helper()
	s := scenario(t)
	s.Roles = append(s.Roles, pvefake.Role{ID: "Console", Privs: []string{"VM.Console"}})
	s.Tokens = append(s.Tokens, pvefake.Token{
		ID: "alice@pve!one", Secret: "k",
		ACL: []pvefake.ACE{{Path: "/", Role: "Console"}},
	})
	f, srv := start(t, s)
	return &taskWorld{f: f}, srv
}

func consoleProxy(t *testing.T, srv *httptest.Server, endpoint string) consoleAnswer {
	t.Helper()
	form := "websocket=1&generate-password=1"
	if endpoint == "termproxy" {
		form = "serial=serial3"
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+"/api2/json/nodes/pve1/qemu/100/"+endpoint, strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "PVEAPIToken=alice@pve!one=k")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var env struct{ Data consoleAnswer }
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || env.Data.Port < 1 ||
		env.Data.Ticket == "" || env.Data.User != "alice@pve" {
		t.Fatalf("proxy %s: status=%d port=%d user=%q ticket set=%t",
			endpoint, resp.StatusCode, env.Data.Port, env.Data.User, env.Data.Ticket != "")
	}
	return env.Data
}

func websocketPath(answer consoleAnswer) string {
	return "/nodes/pve1/qemu/100/vncwebsocket?port=" + strconv.Itoa(answer.Port) +
		"&vncticket=" + url.QueryEscape(answer.Ticket)
}

func consoleRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api2/json"+target, nil)
	req.Header.Set("Authorization", "PVEAPIToken=alice@pve!one=k")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	return req
}

func openConsole(t *testing.T, srv *httptest.Server, req *http.Request) int {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(t.Context(), "tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = fmt.Fprintf(conn, "%s %s %s\r\nHost: %s\r\n", req.Method, req.URL.RequestURI(), req.Proto, u.Host)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Header.Write(conn); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return resp.StatusCode
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("handshake: %s %v", resp.Status, resp.Header)
	}
	frame := make([]byte, 14)
	if _, err := io.ReadFull(reader, frame); err != nil {
		t.Fatal(err)
	}
	if string(frame) != "\x82\x0cRFB 003.008\n" {
		t.Fatalf("frame = %q", frame)
	}
	return resp.StatusCode
}

func TestConsoleTicketsOpenOneWebsocket(t *testing.T) {
	w, srv := consoleWorld(t)
	w.f.SetQuorate(false)
	for _, endpoint := range []string{"vncproxy", "termproxy"} {
		t.Run(endpoint, func(t *testing.T) {
			answer := consoleProxy(t, srv, endpoint)
			kind := "vncproxy"
			if endpoint == "vncproxy" {
				if answer.Cert == "" || answer.Password == "" {
					t.Fatalf("cert set=%t, generated password set=%t", answer.Cert != "", answer.Password != "")
				}
			} else {
				kind = "vncterm"
			}
			if st := w.status(t, answer.UPID); st.Type != kind || st.ExitStatus != "OK" {
				t.Fatalf("console task: %+v", st)
			}
			for _, target := range []string{
				strings.Replace(websocketPath(answer), "/pve1/qemu/100/", "/pve2/qemu/101/", 1),
				strings.Replace(websocketPath(answer), "/100/", "/9000/", 1),
				strings.Replace(websocketPath(answer), "port=5900", "port=5901", 1),
				strings.Replace(websocketPath(answer), url.QueryEscape(answer.Ticket), "made-up", 1),
			} {
				var env struct{ Message string }
				w.call(t, http.MethodGet, target, "alice@pve!one", 401, &env)
				if env.Message != "permission denied - invalid PVEVNC ticket\n" {
					t.Fatalf("invalid ticket: %q", env.Message)
				}
			}
			if got := openConsole(t, srv, consoleRequest(t, websocketPath(answer))); got != http.StatusSwitchingProtocols {
				t.Fatalf("websocket status = %d", got)
			}
			w.call(t, http.MethodGet, websocketPath(answer), "alice@pve!one", 401, nil)
		})
	}
}

func TestConsolePathsRequireConsolePrivilege(t *testing.T) {
	w, srv := consoleWorld(t)
	base := "/nodes/pve1/qemu/100/"
	for _, endpoint := range []string{"vncproxy", "termproxy", "vncwebsocket"} {
		method := http.MethodPost
		if endpoint == "vncwebsocket" {
			method = http.MethodGet
		}
		w.call(t, method, base+endpoint, auditor, 403, nil)
		w.call(t, method, base+endpoint, "unknown@pve!token", 401, nil)
		w.call(t, method, base+endpoint+"?unknown=1", "alice@pve!one", 400, nil)
	}
	for _, target := range []string{
		"vncproxy?websocket=true", "vncproxy?generate-password=2", "vncproxy?serial=serial0",
		"vncproxy?websocket=1&websocket=0", "termproxy?serial=serial4", "termproxy?websocket=1",
	} {
		w.call(t, http.MethodPost, base+target, "alice@pve!one", 400, nil)
	}
	for _, target := range []string{
		"vncwebsocket", "vncwebsocket?port=5900", "vncwebsocket?vncticket=x",
		"vncwebsocket?port=bad&vncticket=x",
	} {
		w.call(t, http.MethodGet, base+target, "alice@pve!one", 400, nil)
	}
	for target, want := range map[string]int{
		"/nodes/nope/qemu/100/vncproxy": 500, "/nodes/pve1/qemu/101/vncproxy": 500,
		"/nodes/pve1/qemu/999/vncproxy": 500, "/nodes/pve1/qemu/99/vncproxy": 400,
	} {
		w.call(t, http.MethodPost, target, "alice@pve!one", want, nil)
	}
	answer := consoleProxy(t, srv, "vncproxy")
	w.call(t, http.MethodGet, websocketPath(answer), "alice@pve!one", 400, nil)
	if got := openConsole(t, srv, consoleRequest(t, websocketPath(answer))); got != http.StatusSwitchingProtocols {
		t.Fatalf("websocket status = %d", got)
	}
}

func TestConsoleHandshakePreservesTicketsOnRefusal(t *testing.T) {
	_, srv := consoleWorld(t)
	for _, tc := range []struct {
		name string
		edit func(*http.Request)
		want int
	}{
		{"split connection", func(r *http.Request) {
			r.Header.Set("Connection", "keep-alive")
			r.Header.Add("Connection", "close, uPgRaDe")
		}, http.StatusSwitchingProtocols},
		{"head", func(r *http.Request) { r.Method = http.MethodHead }, http.StatusBadRequest},
		{"http 1.0", func(r *http.Request) {
			r.Proto, r.ProtoMinor = "HTTP/1.0", 0
		}, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answer := consoleProxy(t, srv, "vncproxy")
			req := consoleRequest(t, websocketPath(answer))
			tc.edit(req)
			if got := openConsole(t, srv, req); got != tc.want {
				t.Fatalf("handshake status = %d, want %d", got, tc.want)
			}
			if tc.want == http.StatusBadRequest {
				req := consoleRequest(t, websocketPath(answer))
				if got := openConsole(t, srv, req); got != http.StatusSwitchingProtocols {
					t.Fatalf("refused handshake consumed ticket: status = %d", got)
				}
			}
		})
	}
}
