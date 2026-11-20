package proxmox

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// member is one node of a three-node cluster: its own fake behind its own
// TLS address. cutWrites makes it read a POST, apply it and then drop the
// connection without answering.
type member struct {
	srv        *httptest.Server
	fake       *pvefake.Fake
	front      *tcpFront // the address registered for the first member; nil for the others
	cutWrites  atomic.Bool
	stallReads atomic.Bool // GETs get no answer: TLS is up, headers never come
	release    chan struct{}
}

// down makes the address refuse connections.
func (m *member) down() {
	if m.front != nil {
		m.front.close()
	}
	m.srv.Close()
}

// tcpFront forwards TCP to a TLS server and can instead accept connections
// and never answer, so the TLS handshake stalls.
type tcpFront struct {
	ln     net.Listener
	target string
	stall  atomic.Bool
	mu     sync.Mutex
	conns  []net.Conn
}

func newFront(t *testing.T, target string) *tcpFront {
	t.Helper()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &tcpFront{ln: ln, target: target}
	go f.serve()
	t.Cleanup(f.close)
	return f
}

func (f *tcpFront) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.conns = append(f.conns, c)
		f.mu.Unlock()
		if f.stall.Load() {
			continue // held open, never answered
		}
		d := net.Dialer{}
		up, err := d.DialContext(context.Background(), "tcp", f.target)
		if err != nil {
			_ = c.Close()
			continue
		}
		f.mu.Lock()
		f.conns = append(f.conns, up)
		f.mu.Unlock()
		go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
		go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
	}
}

// startStalling drops the live connections and holds every new one.
func (f *tcpFront) startStalling() {
	f.stall.Store(true)
	f.dropConns()
}

func (f *tcpFront) dropConns() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.conns {
		_ = c.Close()
	}
	f.conns = nil
}

func (f *tcpFront) close() {
	_ = f.ln.Close()
	f.dropConns()
}

func (m *member) posts() int {
	n := 0
	for _, r := range m.fake.Requests() {
		if strings.HasPrefix(r, "POST ") {
			n++
		}
	}
	return n
}

func newCluster(t *testing.T, size int) ([]*member, *Connection) {
	t.Helper()
	members := make([]*member, size)
	urls := make([]string, size)
	for i := range members {
		s := backupScenario()
		name := "pve" + string(rune('1'+i))
		s.Nodes = []pvefake.Node{{Name: name}}
		s.Storages = []pvefake.Storage{{Node: name, Name: "local"}}
		f, err := pvefake.New(s)
		if err != nil {
			t.Fatal(err)
		}
		m := &member{fake: f, release: make(chan struct{})}
		m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && m.stallReads.Load() {
				select {
				case <-r.Context().Done():
				case <-m.release:
				}
				return
			}
			if r.Method == http.MethodPost && m.cutWrites.Load() {
				// PVE applies the write, then the answer is lost.
				f.ServeHTTP(httptest.NewRecorder(), r)
				if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
					_ = conn.Close()
				}
				return
			}
			f.ServeHTTP(w, r)
		}))
		t.Cleanup(func() { close(m.release) })
		t.Cleanup(m.srv.Close)
		members[i], urls[i] = m, m.srv.URL
		m.front = newFront(t, m.srv.Listener.Addr().String())
		urls[i] = "https://" + m.front.ln.Addr().String()
	}
	dir := privateDir(t)
	writeFixture(t, filepath.Join(dir, "region.yaml"),
		[]byte("read_only: false\npools: {project: managed, nested: parent/child}\n"))
	conn, err := Open(filepath.Join(dir, "region.yaml"), "pve-test-1", filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	data, err := json.Marshal(map[string]any{
		"region": "pve-test-1", "cluster_name": "test", "pveApiUrls": urls, "caPem": serverCA(members[0].srv),
		"tokenId": "vws@pve!inventory", "token": "fake-secret",
		"firewallTokenId": "vws@pve!firewall", "firewallToken": firewallSecret,
		"backupTokenId": "vws@pve!backup", "backupToken": backupSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Register(t.Context(), data); err != nil {
		t.Fatal(err)
	}
	return members, conn
}

func TestFailoverSkipsAFirstAddressThatIsDown(t *testing.T) {
	members, conn := newCluster(t, 3)
	b, err := conn.Check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	members[0].down()
	if _, err := b.client.Nodes(t.Context()); err != nil {
		t.Fatalf("read with the first address down: %v", err)
	}
	NewQuorumGate(b).check(t.Context()) // the address now in use reports quorum
	if err := b.firewall.CreateFirewallGroup(t.Context(), "failover", "test"); err != nil {
		t.Fatalf("mutation with the first address down: %v", err)
	}
	if members[1].posts() != 1 || members[2].posts() != 0 {
		t.Fatalf("POSTs second=%d third=%d, want 1 and 0", members[1].posts(), members[2].posts())
	}
	if b.endpoints.Index() != 1 {
		t.Fatalf("current address %d, want the second", b.endpoints.Index())
	}
}

func TestFailoverNeverResendsAWriteThatWasSent(t *testing.T) {
	members, conn := newCluster(t, 3)
	b, err := conn.Check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	NewQuorumGate(b).check(t.Context())
	members[0].cutWrites.Store(true)
	if err := b.firewall.CreateFirewallGroup(t.Context(), "once", "test"); err == nil {
		t.Fatal("a write whose answer was lost reported success")
	}
	counts := []int{members[0].posts(), members[1].posts(), members[2].posts()}
	if !slices.Equal(counts, []int{1, 0, 0}) {
		t.Fatalf("POSTs per address %v, want [1 0 0]", counts)
	}
	// The caller reconciles by reading PVE: the group exists exactly once.
	groups := 0
	for _, r := range members[0].fake.Requests() {
		if r == "POST /api2/json/cluster/firewall/groups" {
			groups++
		}
	}
	if groups != 1 {
		t.Fatalf("the write reached PVE %d times", groups)
	}
}

func TestGateLeavesAnAddressWithoutQuorumWithinFiveSeconds(t *testing.T) {
	members, conn := newCluster(t, 3)
	b, err := conn.Check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	members[0].fake.SetQuorate(false)
	members[1].fake.SetQuorate(false)
	gate := NewQuorumGate(b)
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan struct{})
	defer func() {
		stop()
		<-done // no probe may still hold a TLS connection when the test ends
	}()
	started := time.Now()
	go func() {
		defer close(done)
		gate.Run(ctx)
	}()
	for gate.Admit(ctx) != nil {
		if time.Since(started) > 5*time.Second {
			t.Fatal("the gate stayed on addresses without quorum for 5 s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if gate.APINode() != "pve3" || b.endpoints.Index() != 2 {
		t.Fatalf("apiNode %q, address %d, want pve3 and the third", gate.APINode(), b.endpoints.Index())
	}
	// Mutations now go to the node that has quorum.
	if err := b.firewall.CreateFirewallGroup(ctx, "quorate", "test"); err != nil {
		t.Fatal(err)
	}
	if members[0].posts()+members[1].posts() != 0 || members[2].posts() != 1 {
		t.Fatal("a write reached a node without quorum")
	}
}

func TestGateLeavesAnAddressThatIsDown(t *testing.T) {
	members, conn := newCluster(t, 2)
	b, err := conn.Check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	members[0].down()
	gate := NewQuorumGate(b)
	gate.check(t.Context())
	if err := gate.Admit(t.Context()); err != nil || gate.APINode() != "pve2" {
		t.Fatalf("Admit = %v, apiNode %q, want admitted on pve2", err, gate.APINode())
	}
}

func TestGateWithNoQuorumAnywhereStaysClosedAndTriesEachAddressOnce(t *testing.T) {
	members, conn := newCluster(t, 3)
	b, err := conn.Check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		m.fake.SetQuorate(false)
	}
	before := make([]int, len(members))
	for i, m := range members {
		before[i] = len(m.fake.Requests())
	}
	gate := NewQuorumGate(b)
	gate.check(t.Context())
	if resource.CodeOf(gate.Admit(t.Context())) != resource.CodeUnavailable {
		t.Fatal("the gate admitted without quorum anywhere")
	}
	for i, m := range members {
		if n := len(m.fake.Requests()) - before[i]; n != 1 {
			t.Errorf("address %d probed %d times in one check, want 1", i, n)
		}
	}
}

func TestFailoverKeepsTheConsoleOnTheAddressThatIssuedTheTicket(t *testing.T) {
	s := inventoryScenario()
	s.Roles = append(s.Roles, pvefake.Role{ID: "Console", Privs: []string{"VM.Console", "VM.Audit", "Pool.Audit"}})
	s.Tokens[0].ACL = append(s.Tokens[0].ACL, pvefake.ACE{Path: "/pool/123456789012", Role: "Console"})
	var servers []*httptest.Server
	var urls []string
	for range 2 {
		f, err := pvefake.New(s)
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewTLSServer(f)
		t.Cleanup(srv.Close)
		servers, urls = append(servers, srv), append(urls, srv.URL)
	}
	dead := httptest.NewTLSServer(nil)
	deadURL := dead.URL
	dead.Close()
	urls = append([]string{deadURL}, urls...)
	base, ok := servers[0].Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("httptest client transport is not an *http.Transport")
	}
	t.Cleanup(base.CloseIdleConnections) // before the servers close, so no connection ends after the test
	endpoints, err := pveclient.NewEndpoints(base, urls, errNoQuorum())
	if err != nil {
		t.Fatal(err)
	}
	for i := range urls {
		endpoints.MarkQuorate(i, time.Now()) // the console ticket is a POST
	}
	client, err := pveclient.New(pveclient.Config{
		BaseURL: urls[0], TokenID: s.Tokens[0].ID, Secret: pveclient.Secret(s.Tokens[0].Secret),
		HTTPClient: &http.Client{Transport: endpoints, Timeout: 10 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(t.Context(), client, registration(), RegionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := NewIDs("test")
	id, _, _ := ids.Instance(VM{UUID: option(s.VMs[0].Config["smbios1"], "uuid")})
	session, err := b.OpenConsole(t.Context(), inventoryScope(), id, resource.ConsoleVNC)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := session.Dial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_, reader, err := stream.NextReader()
	if err != nil {
		t.Fatal(err)
	}
	if banner, err := io.ReadAll(reader); err != nil || string(banner) != "RFB 003.008\n" {
		t.Fatalf("banner %q: %v", banner, err)
	}
}

func startGate(t *testing.T, b *Backend) (gate *QuorumGate, stop func()) {
	t.Helper()
	gate = NewQuorumGate(b)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		gate.Run(ctx)
	}()
	return gate, func() {
		cancel()
		<-done // no probe may still hold a TLS connection when the test ends
	}
}

func TestGateReachesAHealthyAddressPastAStalledOne(t *testing.T) {
	for name, stall := range map[string]func(*member){
		"immediate refusal":     func(m *member) { m.down() },
		"stalled TLS handshake": func(m *member) { m.front.startStalling() },
		"stalled HTTP response": func(m *member) { m.stallReads.Store(true) },
	} {
		t.Run(name, func(t *testing.T) {
			members, conn := newCluster(t, 3)
			b, err := conn.Check(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			stall(members[0])
			started := time.Now()
			gate, stop := startGate(t, b)
			defer stop()
			for gate.Admit(t.Context()) != nil {
				if time.Since(started) > 5*time.Second {
					t.Fatal("the gate did not open within 5 s")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if gate.APINode() != "pve2" || b.endpoints.Index() != 1 {
				t.Fatalf("apiNode %q, address %d, want pve2 and the second", gate.APINode(), b.endpoints.Index())
			}
			if err := b.firewall.CreateFirewallGroup(t.Context(), "stalled", "test"); err != nil {
				t.Fatalf("write after the walk: %v", err)
			}
			if members[1].posts() != 1 || members[0].posts()+members[2].posts() != 0 {
				t.Fatal("the write did not go to the one address with quorum")
			}
		})
	}
}

func TestAdmissionClosesWhenTheIndexMovesToAnUncheckedAddress(t *testing.T) {
	members, conn := newCluster(t, 3)
	b, err := conn.Check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	members[1].fake.SetQuorate(false)
	members[2].fake.SetQuorate(false)
	gate := NewQuorumGate(b)
	gate.check(t.Context())
	if err := gate.Admit(t.Context()); err != nil {
		t.Fatal(err)
	}
	// A read fails over from the quorate address to one nobody has checked.
	members[0].down()
	if _, err := b.client.Nodes(t.Context()); err != nil || b.endpoints.Index() != 1 {
		t.Fatalf("read: %v, address %d", err, b.endpoints.Index())
	}
	wantUnavailable(t, gate.Admit(t.Context()), "an unchecked address")
	err = b.firewall.CreateFirewallGroup(t.Context(), "unchecked", "test")
	if resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("write to an unchecked address: %v", err)
	}
	if members[1].posts() != 0 {
		t.Fatal("a write reached an address with no quorum result")
	}
	members[1].fake.SetQuorate(true)
	gate.check(t.Context())
	if err := gate.Admit(t.Context()); err != nil {
		t.Fatalf("after the gate checked the new address: %v", err)
	}
}

func TestWriteRetryNeverReachesAnUncheckedAddress(t *testing.T) {
	members, conn := newCluster(t, 3)
	b, err := conn.Check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// Only the first address reports quorum, so only it is marked.
	members[1].fake.SetQuorate(false)
	members[2].fake.SetQuorate(false)
	NewQuorumGate(b).check(t.Context())
	members[0].down()
	err = b.firewall.CreateFirewallGroup(t.Context(), "retry", "test")
	if resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("write: %v, want Unavailable", err)
	}
	if members[1].posts()+members[2].posts() != 0 {
		t.Fatal("the pre-connect retry reached an unchecked address")
	}
}

func TestGateWalkReachesTheHealthyAddressPastTwoStalledOnes(t *testing.T) {
	for name, stall := range map[string]func(*member){
		"stalled HTTP responses": func(m *member) { m.stallReads.Store(true) },
		"stalled TLS handshakes": func(m *member) { m.front.startStalling() },
	} {
		t.Run(name, func(t *testing.T) {
			members, conn := newCluster(t, 3)
			b, err := conn.Check(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			stall(members[0])
			stall(members[1])
			before := len(members[2].fake.Requests())
			started := time.Now()
			gate := NewQuorumGate(b)
			gate.check(t.Context()) // the first walk
			if took := time.Since(started); took > 5*time.Second {
				t.Fatalf("the first walk took %s", took)
			}
			if err := gate.Admit(t.Context()); err != nil {
				t.Fatalf("the gate stayed closed after one walk: %v", err)
			}
			if gate.APINode() != "pve3" || b.endpoints.Index() != 2 || len(members[2].fake.Requests()) == before {
				t.Fatalf("apiNode %q, address %d, healthy requests %d",
					gate.APINode(), b.endpoints.Index(), len(members[2].fake.Requests())-before)
			}
		})
	}
}

func TestGateKeepsAQuorateCurrentAddressAndHoldsWhenNoneIs(t *testing.T) {
	members, conn := newCluster(t, 3)
	b, err := conn.Check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	b.endpoints.Use(1)
	gate := NewQuorumGate(b)
	gate.check(t.Context())
	if b.endpoints.Index() != 1 || gate.APINode() != "pve2" {
		t.Fatalf("a quorate current address was left: address %d, apiNode %q", b.endpoints.Index(), gate.APINode())
	}
	for _, m := range members {
		m.fake.SetQuorate(false)
	}
	gate.check(t.Context())
	if b.endpoints.Index() != 1 {
		t.Fatalf("the index moved to %d with no quorate address", b.endpoints.Index())
	}
	wantUnavailable(t, gate.Admit(t.Context()), "no quorate address")
}
