package pvefake

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

type consoleTicket struct {
	node string
	vmid int
	port int
}

func (f *Fake) consoleRoutes() {
	for _, endpoint := range []string{"vncproxy", "termproxy"} {
		f.handleMethod(http.MethodPost, "/nodes/{node}/qemu/{vmid}/"+endpoint, f.consoleProxy)
	}
	f.mux.HandleFunc("GET /api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket", f.consoleWebsocket)
}

func (f *Fake) consoleGuest(t *Token, r *http.Request) (*VM, *failure) {
	node, fail := f.node(r)
	if fail != nil {
		return nil, fail
	}
	vmid, err := strconv.Atoi(r.PathValue("vmid"))
	if err != nil || vmid < 100 || vmid > 999999999 {
		return nil, parameter("vmid", "value does not match a valid VM ID")
	}
	if fail := f.need(t, "/vms/"+strconv.Itoa(vmid), "VM.Console"); fail != nil {
		return nil, fail
	}
	vm := f.vm(vmid)
	if vm == nil || vm.Node != node {
		return nil, &failure{
			http.StatusInternalServerError,
			fmt.Sprintf("Configuration file 'nodes/%s/qemu-server/%d.conf' does not exist", node, vmid),
		}
	}
	return vm, nil
}

func (f *Fake) consoleProxy(t *Token, r *http.Request) (any, *failure) {
	vm, fail := f.consoleGuest(t, r)
	if fail != nil {
		return nil, fail
	}
	if err := r.ParseForm(); err != nil {
		return nil, parameter("body", "unable to parse parameters")
	}
	terminal := strings.HasSuffix(r.URL.Path, "/termproxy")
	for key, values := range r.Form {
		if len(values) != 1 {
			return nil, parameter(key, "repeated parameter")
		}
		switch {
		case !terminal && (key == "websocket" || key == "generate-password"):
			if values[0] != "0" && values[0] != "1" {
				return nil, parameter(key, "type check ('boolean') failed")
			}
		case terminal && key == "serial":
			if !slices.Contains([]string{"serial0", "serial1", "serial2", "serial3"}, values[0]) {
				return nil, parameter(key, "value is not in the enumeration")
			}
		default:
			return nil, parameter(key, "property is not defined in the fake's console schema")
		}
	}
	ticket := rand.Text()
	port := 5900
	f.tickets[ticket] = consoleTicket{node: vm.Node, vmid: vm.VMID, port: port}
	kind := "vncproxy"
	if terminal {
		kind = "vncterm"
	}
	user, _, _ := strings.Cut(t.ID, "!")
	row := map[string]any{
		"port": port, "ticket": ticket, "user": user,
		"upid": f.submit(t, vm.Node, kind, strconv.Itoa(vm.VMID), func() string { return "OK" }),
	}
	if !terminal {
		row["cert"] = "pvefake console certificate"
		if r.Form.Get("generate-password") == "1" {
			row["password"] = rand.Text()
		}
	}
	return row, nil
}

// consumeConsoleTicket runs under mu; the socket must never keep API state locked.
func (f *Fake) consumeConsoleTicket(r *http.Request) *failure {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settle()
	t := f.token(r.Header.Get("Authorization"))
	if t == nil {
		return &failure{http.StatusUnauthorized, "authentication failure"}
	}
	vm, fail := f.consoleGuest(t, r)
	if fail != nil {
		return fail
	}
	q := r.URL.Query()
	for key, values := range q {
		if (key != "port" && key != "vncticket") || len(values) != 1 {
			return parameter(key, "unknown or repeated parameter")
		}
	}
	port, err := strconv.Atoi(q.Get("port"))
	if err != nil || port < 1 || port > 65535 {
		return parameter("port", "invalid integer")
	}
	if q.Get("vncticket") == "" {
		return parameter("vncticket", "missing parameter")
	}
	ticket, ok := f.tickets[q.Get("vncticket")]
	if !ok || ticket.node != vm.Node || ticket.vmid != vm.VMID || ticket.port != port {
		return &failure{http.StatusUnauthorized, "permission denied - invalid PVEVNC ticket"}
	}
	key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
	if r.Method != http.MethodGet || !r.ProtoAtLeast(1, 1) ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || err != nil || len(key) != 16 ||
		r.Header.Get("Sec-WebSocket-Version") != "13" ||
		!slices.ContainsFunc(r.Header.Values("Connection"), func(value string) bool {
			return slices.ContainsFunc(strings.Split(value, ","), func(token string) bool {
				return strings.EqualFold(strings.TrimSpace(token), "upgrade")
			})
		}) {
		return parameter("websocket", "invalid websocket handshake")
	}
	delete(f.tickets, q.Get("vncticket"))
	return nil
}

func (f *Fake) consoleWebsocket(w http.ResponseWriter, r *http.Request) {
	if fail := f.consumeConsoleTicket(r); fail != nil {
		reply(w, nil, fail)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		reply(w, nil, &failure{http.StatusInternalServerError, "websocket transport unavailable"})
		return
	}
	conn, buf, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close() //nolint:errcheck // the handshake has no remaining HTTP response channel
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	if _, err := fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"+
		"Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
		return
	}
	if _, err := buf.Write(append([]byte{0x82, 12}, []byte("RFB 003.008\n")...)); err != nil {
		return
	}
	if err := buf.Flush(); err != nil {
		return
	}
}
