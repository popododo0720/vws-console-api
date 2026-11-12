package proxmox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-lib/obs"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type leaseHelper struct {
	fs *pvefake.PMXCFS
}

func (h leaseHelper) Lock(_ context.Context, name string) error {
	return h.fs.Mkdir("/etc/pve/priv/lock/vws-region/" + name)
}

func (h leaseHelper) Unlock(_ context.Context, name string) error {
	return h.fs.Remove("/etc/pve/priv/lock/vws-region/" + name)
}

func (h leaseHelper) WriteLease(_ context.Context, data []byte) error {
	return h.fs.WriteFile(leaderPath, data)
}

type leaseClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *leaseClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *leaseClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func testLeader(t *testing.T, s pvefake.Scenario) (*Leader, *pvefake.Fake, *leaseClock) {
	t.Helper()
	client, fake := serve(t, s)
	b, err := New(t.Context(), client, registration(), RegionConfig{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	leader, err := NewLeader(t.Context(), b, leaseHelper{fake.PMXCFS()}, leaderPath)
	if err != nil {
		t.Fatal(err)
	}
	fs := fake.PMXCFS()
	for _, dir := range []string{
		"/etc/pve/vws", "/etc/pve/priv", "/etc/pve/priv/lock", "/etc/pve/priv/lock/vws-region",
	} {
		if err := fs.Mkdir(dir); err != nil {
			t.Fatal(err)
		}
	}
	clock := &leaseClock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	leader.now, leader.read = clock.now, fs.ReadFile
	return leader, fake, clock
}

func acquireLeader(t *testing.T, leader *Leader) {
	t.Helper()
	leader.checkQuorum(t.Context())
	if err := leader.renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	if peer, err := leader.Admit(t.Context()); peer != "" || err != nil {
		t.Fatalf("leader admission: peer=%q err=%v", peer, err)
	}
}

func TestLeaderFenceHasNoPVECalls(t *testing.T) {
	for _, remaining := range []time.Duration{5*time.Second + time.Nanosecond, 5 * time.Second, 0} {
		t.Run(remaining.String(), func(t *testing.T) {
			leader, fake, clock := testLeader(t, scenario())
			acquireLeader(t, leader)
			clock.advance(20*time.Second - remaining)
			leader.checkQuorum(t.Context())
			before := len(fake.Requests())
			_, err := leader.Admit(t.Context())
			if (err == nil) != (remaining > 5*time.Second) {
				t.Fatalf("remaining=%s admission=%v", remaining, err)
			}
			if err != nil && resource.CodeOf(err) != resource.CodeUnavailable {
				t.Fatal(err)
			}
			if len(fake.Requests()) != before {
				t.Fatal("admission issued a PVE request")
			}
		})
	}
	leader, fake, clock := testLeader(t, scenario())
	acquireLeader(t, leader)
	fake.SetQuorate(false)
	before := len(fake.Requests())
	clock.advance(2 * time.Second)
	leader.checkQuorum(t.Context())
	at := len(fake.Requests())
	if _, err := leader.Admit(t.Context()); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("lost quorum admission: %v", err)
	}
	if len(fake.Requests()) != at {
		t.Fatal("quorum fence issued a PVE request")
	}
	for _, request := range fake.Requests()[before:] {
		if !strings.HasPrefix(request, "GET ") {
			t.Fatalf("mutation after quorum loss: %s", request)
		}
	}
	if err := leader.helper.WriteLease(t.Context(), []byte("{}")); err == nil {
		t.Fatal("pmxcfs remained writable without quorum")
	}
	if leader.Current() != "" || leader.Quorate() {
		t.Fatal("lost quorum retained leadership")
	}
	fake.SetQuorate(true)
	leader.checkQuorum(t.Context())
	if err := leader.renew(t.Context()); err != nil || leader.Current() != "" {
		t.Fatal("recovered node renewed a lease it relinquished", err)
	}
}

func leaderFollower(t *testing.T, first *Leader, node string, clock *leaseClock) *Leader {
	t.Helper()
	next, err := NewLeader(t.Context(), first.backend, first.helper, leaderPath)
	if err != nil {
		t.Fatal(err)
	}
	next.node, next.read, next.now = node, first.read, clock.now
	return next
}

func TestLeaderLeaseTakeoverAndRenewal(t *testing.T) {
	first, fake, clock := testLeader(t, scenario())
	acquireLeader(t, first)
	second := leaderFollower(t, first, "pve2", clock)
	second.checkQuorum(t.Context())
	if err := second.renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	if peer, err := second.Admit(t.Context()); peer != "pve1" || err != nil {
		t.Fatalf("follower peer=%q err=%v", peer, err)
	}
	clock.advance(5 * time.Second)
	acquireLeader(t, first)
	if first.lease.Term != 1 || first.lease.Until.Sub(clock.now()) != 20*time.Second {
		t.Fatalf("renewed lease=%+v", first.lease)
	}
	clock.advance(20 * time.Second)
	second.checkQuorum(t.Context())
	if err := second.renew(t.Context()); err != nil || second.ownedTerm != 0 {
		t.Fatalf("takeover at exact expiry: term=%d err=%v", second.ownedTerm, err)
	}
	clock.advance(time.Nanosecond)
	acquireLeader(t, second)
	if second.lease.Term != 2 {
		t.Fatalf("takeover term=%d", second.lease.Term)
	}
	restarted := leaderFollower(t, second, "pve2", clock)
	restarted.checkQuorum(t.Context())
	if err := restarted.renew(t.Context()); err != nil || restarted.ownedTerm != 0 {
		t.Fatal("restart renewed another process's lease", err)
	}
	if _, err := first.Admit(t.Context()); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("old leader admitted after expiry: %v", err)
	}
	if err := fake.PMXCFS().WriteFile(leaderPath, []byte("broken")); err != nil {
		t.Fatal(err)
	}
	if err := second.renew(t.Context()); err == nil || second.Current() != "" {
		t.Fatal("corrupt lease did not fail closed")
	}
}

type leaderLog struct {
	mu      sync.Mutex
	data    bytes.Buffer
	changed chan struct{}
}

func (l *leaderLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.data.Write(p)
	select {
	case l.changed <- struct{}{}:
	default:
	}
	return n, err
}

func TestLeaderLoopQuorumAndLogs(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("VWS_HEALTH_ADDR", "")
	logs := &leaderLog{changed: make(chan struct{}, 1)}
	previous := slog.Default()
	defer slog.SetDefault(previous)
	shutdown, err := obs.Setup(t.Context(), obs.ForService("vws-region"), obs.WithOverride(func(c *obs.Config) {
		c.LogOutput = logs
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := shutdown(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	}()
	leader, fake, clock := testLeader(t, scenario())
	ticks := make(chan time.Time)
	leader.ticks = func(d time.Duration) (<-chan time.Time, func()) {
		if d == 2*time.Second {
			return ticks, func() {}
		}
		return make(chan time.Time), func() {}
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); leader.Run(ctx) }()
	defer cancel()
	waitChange := func() []byte {
		t.Helper()
		timeout, stop := context.WithTimeout(t.Context(), 5*time.Second)
		defer stop()
		for {
			select {
			case <-logs.changed:
				logs.mu.Lock()
				data := bytes.Clone(logs.data.Bytes())
				logs.data.Reset()
				logs.mu.Unlock()
				for _, line := range bytes.Split(data, []byte("\n")) {
					if bytes.Contains(line, []byte("region leader changed")) {
						return line
					}
				}
			case <-timeout.Done():
				t.Fatal("leader event timed out")
			}
		}
	}
	if line := waitChange(); !bytes.Contains(line, []byte("pve1")) {
		t.Fatalf("leader log=%s", line)
	}
	fake.SetQuorate(false)
	before := len(fake.Requests())
	clock.advance(2 * time.Second)
	select {
	case ticks <- clock.now():
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not accept fake tick")
	}
	waitChange()
	if _, err := leader.Admit(t.Context()); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatal("loop admitted without quorum", err)
	}
	for _, request := range fake.Requests()[before:] {
		if !strings.HasPrefix(request, "GET ") {
			t.Fatal("mutation after quorum loss", request)
		}
	}
	fake.SetQuorate(true)
	clock.advance(20 * time.Second)
	second := leaderFollower(t, leader, "pve2", clock)
	acquireLeader(t, second)
	line := waitChange()
	if !bytes.Contains(line, []byte("pve2")) ||
		(!bytes.Contains(line, []byte(`"term":2`)) && !bytes.Contains(line, []byte("term=2"))) {
		t.Fatalf("takeover log=%s", line)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("leader did not stop")
	}
}

func TestLeaderStandaloneAndLeaseErrors(t *testing.T) {
	s := scenario()
	s.Cluster = ""
	leader, fake, clock := testLeader(t, s)
	acquireLeader(t, leader)
	clock.advance(2*time.Second + time.Nanosecond)
	if _, err := leader.Admit(t.Context()); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatal("stale quorum admitted")
	}
	if err := fake.SetNodeOnline("pve1", false); err != nil {
		t.Fatal(err)
	}
	leader.checkQuorum(t.Context())
	if leader.Quorate() {
		t.Fatal("offline standalone node was quorate")
	}
	leader.read = func(string) ([]byte, error) { return nil, errors.New("read failed") }
	if err := leader.renew(t.Context()); err == nil {
		t.Fatal("read failure was ignored")
	}
	for _, lease := range []leaderLease{{}, {Node: "../bad", Term: 1, Until: clock.now()}} {
		data, err := json.Marshal(lease)
		if err != nil {
			t.Fatal(err)
		}
		leader.read = func(string) ([]byte, error) { return data, nil }
		if _, err := leader.readLease(); err == nil {
			t.Fatal("invalid lease accepted")
		}
	}
}
