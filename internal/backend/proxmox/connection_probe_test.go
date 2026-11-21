package proxmox

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/secret"
	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

// memListener is a listener nothing on the network can reach. Only its dial
// method connects to it, so a process without that method cannot reach PVE.
type memListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
	dials atomic.Int32
}

func newMemListener() *memListener {
	return &memListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *memListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }

func (l *memListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }

func (l *memListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	l.dials.Add(1)
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// trap is a real TCP listener that stands where the PVE address points on the
// network. It serves nothing and counts every connection made to it.
type trap struct {
	ln       net.Listener
	accepted atomic.Int32
}

func newTrap(t *testing.T) *trap {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &trap{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tr.accepted.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return tr
}

func (tr *trap) url() string { return "https://" + tr.ln.Addr().String() }

type probeStack struct {
	console   http.Handler
	daemon    *Connection
	pveConns  *memListener
	pve       *pvefake.Fake
	trap      *trap
	ca        string
	regionURL string
	logs      *bytes.Buffer
}

// newProbeStack builds the global side (console handler and regionapi client),
// the daemon (mTLS regionapi server around Connection.TestConnection) and a PVE
// fake. The PVE fake listens only in memory; the address in the registration
// points at a trap that counts connections. daemonCanReach decides whether
// the daemon gets the dialer that reaches the in-memory PVE.
func newProbeStack(t *testing.T, daemonCanReach bool) *probeStack {
	t.Helper()
	pve, err := pvefake.New(scenario())
	if err != nil {
		t.Fatal(err)
	}
	mem := newMemListener()
	upstream := httptest.NewUnstartedServer(pve)
	if err := upstream.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	upstream.Listener = mem
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	daemon, _ := openFixture(t)
	if daemonCanReach {
		daemon.dialPVE = mem.dial
	}
	region := httptest.NewUnstartedServer(regionapi.WithConnectionTest(daemon.TestConnection,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, err := w.Write([]byte(`{"quorum":true}`)); err != nil {
				t.Error(err)
			}
		})))
	region.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert}
	region.StartTLS()
	t.Cleanup(region.Close)
	mtls := region.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	mtls.Certificates = upstream.TLS.Certificates
	client := func(endpoint string) (*regionapi.Client, error) {
		rc, err := regionapi.NewClient(endpoint, mtls)
		if err == nil {
			t.Cleanup(rc.Close)
		}
		return rc, err
	}

	key, err := secret.New("test", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	return &probeStack{
		console: console.New(console.Config{
			Registry: store.New(store.NewMemory()), AdminKey: key,
			Logger: slog.New(slog.NewJSONHandler(logs, nil)), Auth: console.BearerTokens{"root": {Root: true}},
			RegionConnection: func(
				ctx context.Context, endpoint string, data json.RawMessage,
			) ([]resource.ConnectionStep, error) {
				rc, err := client(endpoint)
				if err != nil {
					return nil, err
				}
				return rc.TestConnection(ctx, data)
			},
			RegionStatus: func(ctx context.Context, endpoint string) (resource.RegionStatus, error) {
				rc, err := client(endpoint)
				if err != nil {
					return resource.RegionStatus{}, err
				}
				return rc.Status(ctx)
			},
		}),
		daemon: daemon, pveConns: mem, pve: pve, trap: newTrap(t), ca: serverCA(upstream),
		regionURL: region.URL, logs: logs,
	}
}

// test posts an unsaved region test whose PVE address is the trap.
func (p *probeStack) test(t *testing.T, regionEndpoint string) ([]resource.ConnectionStep, string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"name": "pve-test-1", "clusterName": "test", "pveApiUrls": []string{p.trap.url()},
		"caPem": p.ca, "tokenId": "vws@pve!inventory", "regionEndpoint": regionEndpoint,
		"tokenSecret": "fake-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/admin/regions/test",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer root")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.console.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("test route: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Steps []resource.ConnectionStep `json:"steps"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Steps, rec.Body.String() + p.logs.String()
}

func results(steps []resource.ConnectionStep) string {
	var names []string
	for _, step := range steps {
		names = append(names, step.Name+"="+string(step.Result))
	}
	return strings.Join(names, " ")
}

func TestConnectionTestReachesPVEOnlyFromTheDaemon(t *testing.T) {
	stack := newProbeStack(t, true)
	for range 2 {
		steps, text := stack.test(t, stack.regionURL)
		const want = "tls=PASS version=PASS cluster_name=PASS privileges=PASS regionapi=PASS"
		if got := results(steps); got != want {
			t.Fatalf("steps %s, want %s: %+v", got, want, steps)
		}
		if strings.Contains(text, "fake-secret") {
			t.Fatal("secret leaked into the response or the console log")
		}
	}
	if n := stack.trap.accepted.Load(); n != 0 {
		t.Fatalf("the global process opened %d connections to the PVE address", n)
	}
	if stack.pveConns.dials.Load() == 0 || len(stack.pve.Requests()) == 0 {
		t.Fatal("the daemon never reached PVE")
	}
	for _, request := range stack.pve.Requests() {
		if !strings.HasPrefix(request, "GET ") {
			t.Errorf("test wrote to PVE: %s", request)
		}
	}
}

// Without the daemon's dialer the same address is the trap, so the trap counts
// what a direct dial from the global process would have done.
func TestConnectionTestTrapSeesADirectDial(t *testing.T) {
	stack := newProbeStack(t, false)
	steps, _ := stack.test(t, stack.regionURL)
	if steps[0].Result != resource.ConnectionFail || stack.trap.accepted.Load() == 0 {
		t.Fatalf("the trap missed a dial: %+v, accepted=%d", steps, stack.trap.accepted.Load())
	}
}

func TestConnectionTestWithoutADaemonIsAClearFailure(t *testing.T) {
	stack := newProbeStack(t, true)
	closed := httptest.NewTLSServer(nil)
	endpoint := closed.URL
	closed.Close()
	steps, text := stack.test(t, endpoint)
	if len(steps) != 5 || steps[0].Name != "tls" || steps[0].Result != resource.ConnectionFail ||
		!strings.HasPrefix(steps[0].Message, "PVE checks run in the region daemon, which did not answer") {
		t.Fatalf("an unreachable daemon: %+v", steps)
	}
	for _, step := range steps[1:] {
		if step.Result != resource.ConnectionSkipped {
			t.Errorf("step after the failure: %+v", step)
		}
	}
	if strings.Contains(text, "fake-secret") || stack.trap.accepted.Load() != 0 || len(stack.pve.Requests()) != 0 {
		t.Fatal("a missing daemon still reached PVE or leaked the secret")
	}
}

func TestConnectionTestLeavesTheRegistrationAlone(t *testing.T) {
	live, liveFake := clusterFake(t, "test")
	c, state := openFixture(t)
	if err := c.Register(t.Context(), registerBody(t, []string{live.URL}, serverCA(live))); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(state, registrationFile))
	if err != nil {
		t.Fatal(err)
	}
	backend, err := c.Check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	liveRequests := len(liveFake.Requests())
	candidate, candidateFake := clusterFake(t, "elsewhere")
	data, err := json.Marshal(map[string]any{
		"region": "pve-test-1", "cluster_name": "test", "pveApiUrls": []string{candidate.URL},
		"caPem": serverCA(candidate), "tokenId": "vws@pve!inventory", "token": "fake-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		steps, err := c.TestConnection(t.Context(), data)
		if err != nil || steps[2].Result != resource.ConnectionFail {
			t.Fatalf("candidate with another cluster: %+v %v", steps, err)
		}
	}
	if len(candidateFake.Requests()) == 0 {
		t.Fatal("the candidate was not probed")
	}
	if n := len(liveFake.Requests()); n != liveRequests {
		t.Fatalf("the test sent %d requests to the live registration's PVE", n-liveRequests)
	}
	after, err := os.ReadFile(filepath.Join(state, registrationFile))
	if err != nil || !bytes.Equal(before, after) || bytes.Contains(after, []byte("elsewhere")) {
		t.Fatalf("the test changed the state file: %v", err)
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 1 {
		t.Fatalf("state directory after the test: %v %v", entries, err)
	}
	if again, err := c.Check(t.Context()); err != nil || again != backend {
		t.Fatalf("the live registration changed: %v", err)
	}
}

func TestConnectionTestValidatesLikeRegistration(t *testing.T) {
	srv := clusterServer(t, "test")
	ca := serverCA(srv)
	var dialed atomic.Int32
	c, _ := openFixture(t)
	c.dialPVE = func(context.Context, string, string) (net.Conn, error) {
		dialed.Add(1)
		return nil, net.ErrClosed
	}
	many := make([]string, 17)
	for i := range many {
		many[i] = "https://pve" + string(rune('a'+i)) + ":8006"
	}
	base := func() map[string]any {
		return map[string]any{
			"region": "pve-test-1", "cluster_name": "test", "pveApiUrls": []string{srv.URL}, "caPem": ca,
			"tokenId": "vws@pve!inventory", "token": "fake-secret",
		}
	}
	for name, mutate := range map[string]func(map[string]any){
		"another region": func(m map[string]any) { m["region"] = "pve-other-1" },
		"plain http":     func(m map[string]any) { m["pveApiUrls"] = []string{"http://pve1:8006"} },
		"userinfo":       func(m map[string]any) { m["pveApiUrls"] = []string{"https://u:p@pve1:8006"} },
		"path":           func(m map[string]any) { m["pveApiUrls"] = []string{"https://pve1:8006/api2/json"} },
		"query":          func(m map[string]any) { m["pveApiUrls"] = []string{"https://pve1:8006?x=1"} },
		"duplicate": func(m map[string]any) {
			m["pveApiUrls"] = []string{"https://pve1:8006", "https://PVE1:8006/"}
		},
		"no address":          func(m map[string]any) { m["pveApiUrls"] = []string{} },
		"seventeen addresses": func(m map[string]any) { m["pveApiUrls"] = many },
		"no CA":               func(m map[string]any) { m["caPem"] = "" },
		"CA is not PEM":       func(m map[string]any) { m["caPem"] = "bad" },
		"bad cluster":         func(m map[string]any) { m["cluster_name"] = "../x" },
		"bad token id":        func(m map[string]any) { m["tokenId"] = "root" },
		"no token":            func(m map[string]any) { m["token"] = "" },
		"token with a space":  func(m map[string]any) { m["token"] = "a b" },
		"unknown field":       func(m map[string]any) { m["extra"] = 1 },
		"path-like pool":      func(m map[string]any) { m["pools"] = []string{"../access"} },
	} {
		t.Run(name, func(t *testing.T) {
			m := base()
			mutate(m)
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			steps, err := c.TestConnection(t.Context(), data)
			if e := resource.AsError(err); err == nil || e.Code != resource.CodeInvalidArgument {
				t.Fatalf("accepted: %+v %v", steps, err)
			}
			if strings.Contains(err.Error(), "fake-secret") {
				t.Fatal("the refusal repeats the secret")
			}
		})
	}
	for _, body := range []string{"", "[]", "{} {}", "null"} {
		if _, err := c.TestConnection(t.Context(), json.RawMessage(body)); err == nil {
			t.Errorf("accepted %q", body)
		}
	}
	if n := dialed.Load(); n != 0 {
		t.Fatalf("a refused request still dialed %d times", n)
	}
	data, err := json.Marshal(base())
	if err != nil {
		t.Fatal(err)
	}
	steps, err := c.TestConnection(t.Context(), data)
	if err != nil || steps[0].Result != resource.ConnectionFail || dialed.Load() != 1 {
		t.Fatalf("a valid request: %+v %v dials=%d", steps, err, dialed.Load())
	}
}

// A region may map more pools than any fixed count; the body and time limits
// bound the test, so every mapped pool reaches the checks.
func TestConnectionTestAcceptsManyMappedPools(t *testing.T) {
	srv := clusterServer(t, "test")
	c, _ := openFixture(t)
	pools := make([]string, 257)
	for i := range pools {
		pools[i] = fmt.Sprintf("vws-p%03d", i)
	}
	data, err := json.Marshal(map[string]any{
		"region": "pve-test-1", "cluster_name": "test", "pveApiUrls": []string{srv.URL},
		"caPem": serverCA(srv), "tokenId": "vws@pve!inventory", "token": "fake-secret", "pools": pools,
	})
	if err != nil {
		t.Fatal(err)
	}
	steps, err := c.TestConnection(t.Context(), data)
	if err != nil || len(steps) != 4 || steps[0].Result != resource.ConnectionPass {
		t.Fatalf("257 mapped pools: %+v %v", steps, err)
	}
}
