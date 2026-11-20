package proxmox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
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
	srv       *httptest.Server
	fake      *pvefake.Fake
	cutWrites atomic.Bool
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
		m := &member{fake: f}
		m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		t.Cleanup(m.srv.Close)
		members[i], urls[i] = m, m.srv.URL
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
	members[0].srv.Close()
	if _, err := b.client.Nodes(t.Context()); err != nil {
		t.Fatalf("read with the first address down: %v", err)
	}
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
	members[0].srv.Close()
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
	endpoints, err := pveclient.NewEndpoints(base, urls)
	if err != nil {
		t.Fatal(err)
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
