package pveclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testTokenID = "vws@pve!region"
	testSecret  = "5e0c1f2a-secret-token-value"
)

type call struct {
	name  string
	run   func(context.Context, *Client) (any, error)
	path  string
	query string
	data  string
	want  any
}

var calls = []call{
	{
		"version", func(ctx context.Context, c *Client) (any, error) { return c.Version(ctx) },
		"/api2/json/version", "", `{"version":"8.4.1","release":"8.4","repoid":"abc"}`,
		Version{Version: "8.4.1", Release: "8.4", RepoID: "abc"},
	},
	{
		"cluster status", func(ctx context.Context, c *Client) (any, error) { return c.ClusterStatus(ctx) },
		"/api2/json/cluster/status", "", `[{"type":"node","name":"pve1","online":1,"local":1}]`,
		[]ClusterStatus{{Type: "node", Name: "pve1", Online: 1, Local: 1}},
	},
	{
		"cluster resources", func(ctx context.Context, c *Client) (any, error) {
			return c.ClusterResources(ctx, ResourceVM)
		}, "/api2/json/cluster/resources", "type=vm", `[{"id":"qemu/100","vmid":100,"maxmem":2147483648}]`,
		[]ClusterResource{{ID: "qemu/100", VMID: 100, MaxMem: 2147483648}},
	},
	{
		"nodes", func(ctx context.Context, c *Client) (any, error) { return c.Nodes(ctx) },
		"/api2/json/nodes", "", `[{"node":"pve1","status":"online","maxcpu":4}]`,
		[]Node{{Node: "pve1", Status: "online", MaxCPU: 4}},
	},
	{
		"vm config", func(ctx context.Context, c *Client) (any, error) {
			return c.VMConfig(ctx, VM{Node: "pve1", VMID: 100})
		}, "/api2/json/nodes/pve1/qemu/100/config", "", `{"digest":"d1","name":"i-1","cores":2,"lock":"clone"}`,
		VMConfig{Digest: "d1", Name: "i-1", Lock: "clone", Cores: 2},
	},
	{"snapshots", func(ctx context.Context, c *Client) (any, error) {
		return c.Snapshots(ctx, VM{Node: "pve1", VMID: 100})
	}, "/api2/json/nodes/pve1/qemu/100/snapshot", "", `[{"name":"current"}]`, []Snapshot{{Name: "current"}}},
	{
		"storage content", func(ctx context.Context, c *Client) (any, error) {
			return c.StorageContent(ctx, "pve1", "local-lvm")
		}, "/api2/json/nodes/pve1/storage/local-lvm/content", "", `[{"volid":"local-lvm:vm-100-disk-0","size":8}]`,
		[]StorageContent{{VolID: "local-lvm:vm-100-disk-0", Size: 8}},
	},
	{
		"network", func(ctx context.Context, c *Client) (any, error) { return c.Network(ctx, "pve1") },
		"/api2/json/nodes/pve1/network", "type=any_bridge", `[{"iface":"vmbr0","type":"bridge","active":1}]`,
		[]NetworkInterface{{Iface: "vmbr0", Type: "bridge", Active: 1}},
	},
	{
		"sdn zones", func(ctx context.Context, c *Client) (any, error) { return c.SDNZones(ctx) },
		"/api2/json/cluster/sdn/zones", "", `[{"zone":"z1","type":"simple"}]`,
		[]SDNZone{{Zone: "z1", Type: "simple"}},
	},
	{
		"sdn vnets", func(ctx context.Context, c *Client) (any, error) { return c.SDNVNets(ctx) },
		"/api2/json/cluster/sdn/vnets", "", `[{"vnet":"v1","zone":"z1"}]`,
		[]SDNVNet{{VNet: "v1", Zone: "z1"}},
	},
	{
		"sdn subnets", func(ctx context.Context, c *Client) (any, error) { return c.SDNSubnets(ctx, "v1") },
		"/api2/json/cluster/sdn/vnets/v1/subnets", "", `[{"cidr":"10.0.0.0/24"}]`,
		[]SDNSubnet{{CIDR: "10.0.0.0/24"}},
	},
	{
		"firewall groups", func(ctx context.Context, c *Client) (any, error) { return c.FirewallGroups(ctx) },
		"/api2/json/cluster/firewall/groups", "", `[{"group":"sg-1"}]`,
		[]FirewallGroup{{Group: "sg-1"}},
	},
	{
		"firewall group rules", func(ctx context.Context, c *Client) (any, error) {
			return c.FirewallGroupRules(ctx, "sg-1")
		}, "/api2/json/cluster/firewall/groups/sg-1", "", `[{"pos":0,"type":"in","action":"ACCEPT","dport":"22"}]`,
		[]FirewallRule{{Type: "in", Action: "ACCEPT", DPort: "22"}},
	},
	{
		"access permissions", func(ctx context.Context, c *Client) (any, error) {
			return c.AccessPermissions(ctx, "/vms")
		}, "/api2/json/access/permissions", "path=%2Fvms", `{"/vms":{"VM.Audit":1}}`,
		Permissions{"/vms": {"VM.Audit": 1}},
	},
	{
		"access roles", func(ctx context.Context, c *Client) (any, error) { return c.Roles(ctx) },
		"/api2/json/access/roles", "", `[{"roleid":"PVEAuditor","privs":"VM.Audit"}]`,
		[]Role{{RoleID: "PVEAuditor", Privs: "VM.Audit"}},
	},
	{
		"wait task", func(ctx context.Context, c *Client) (any, error) {
			upid := "UPID:pve1:0000A1B2:00C3D4E5:6720F00D:qmclone:100:vws@pve!region:"
			return nil, c.WaitTask(ctx, Task{Node: "pve1", UPID: upid}, StartWait)
		}, "/api2/json/nodes/pve1/tasks/UPID:pve1:0000A1B2:00C3D4E5:6720F00D:qmclone:100:vws@pve%21region:/status", "",
		`{"status":"stopped","exitstatus":"OK"}`, nil,
	},
}

// deadlines records whether each request carried a context deadline no later than ReadTimeout.
type deadlines struct {
	next   http.RoundTripper
	missed atomic.Int32
}

func (d *deadlines) RoundTrip(r *http.Request) (*http.Response, error) {
	if dl, ok := r.Context().Deadline(); !ok || time.Until(dl) > ReadTimeout {
		d.missed.Add(1)
	}
	return d.next.RoundTrip(r)
}

// fakeClock moves its time forward by d on After and fires at once, so a
// task wait never waits in real time. One client, one goroutine.
type fakeClock struct{ now time.Time }

func (f *fakeClock) Now() time.Time { return f.now }

func (f *fakeClock) After(d time.Duration) <-chan time.Time {
	f.now = f.now.Add(d)
	ch := make(chan time.Time, 1)
	ch <- f.now
	return ch
}

func newClient(t *testing.T, h http.HandlerFunc, log *slog.Logger) (*Client, *deadlines) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	rt := &deadlines{next: srv.Client().Transport}
	c, err := New(Config{
		BaseURL: srv.URL, TokenID: testTokenID, Secret: testSecret, HTTPClient: &http.Client{Transport: rt},
		Log: log, Backoff: time.Millisecond, PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.clock = &fakeClock{now: time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)}
	return c, rt
}

func TestTypedCallsReadTheirPathsWithTheToken(t *testing.T) {
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			c, rt := newClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.EscapedPath() != tc.path || r.URL.RawQuery != tc.query {
					t.Errorf("request %s %s?%s, want GET %s?%s", r.Method, r.URL.EscapedPath(), r.URL.RawQuery, tc.path, tc.query)
				}
				if got := r.Header.Get("Authorization"); got != "PVEAPIToken="+testTokenID+"="+testSecret {
					t.Errorf("Authorization = %q", got)
				}
				fmt.Fprintf(w, `{"data":%s}`, tc.data)
			}, nil)
			got, err := tc.run(t.Context(), c)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want != nil && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
			if n := rt.missed.Load(); n != 0 {
				t.Errorf("%d requests without a context deadline within %v", n, ReadTimeout)
			}
		})
	}
}

func TestRetries(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		message  string
		attempts int32
	}{
		{"500 is retried 3 times then fails", http.StatusInternalServerError, "", 1 + MaxRetries},
		{"596 is retried 3 times then fails", 596, "", 1 + MaxRetries},
		{"403 is not retried", http.StatusForbidden, "Permission check failed", 1},
		{"404 is not retried", http.StatusNotFound, "", 1},
		{"VM is locked is not retried", http.StatusInternalServerError, "VM is locked (clone)", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts atomic.Int32
			c, _ := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
				attempts.Add(1)
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, `{"data":null,"message":%q}`, tc.message)
			}, nil)
			_, err := c.Version(t.Context())
			he, ok := errors.AsType[*HTTPError](err)
			if !ok || he.Status != tc.status {
				t.Fatalf("err = %v, want an HTTPError %d", err, tc.status)
			}
			if got := attempts.Load(); got != tc.attempts {
				t.Errorf("%d attempts, want %d", got, tc.attempts)
			}
		})
	}
}

func TestDroppedConnectionIsRetried(t *testing.T) {
	var attempts atomic.Int32
	c, _ := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) <= MaxRetries {
			conn, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		fmt.Fprint(w, `{"data":{"version":"8.4.1"}}`)
	}, nil)
	v, err := c.Version(t.Context())
	if err != nil || v.Version != "8.4.1" {
		t.Fatalf("Version = %+v, %v", v, err)
	}
	if got := attempts.Load(); got != 1+MaxRetries {
		t.Errorf("%d attempts, want %d", got, 1+MaxRetries)
	}
}

func TestTokenNeverLogged(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	var attempts atomic.Int32
	c, _ := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1)%2 == 0 {
			conn, _, _ := http.NewResponseController(w).Hijack()
			conn.Close()
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	}, log)
	var texts []string
	for _, tc := range calls {
		_, err := tc.run(t.Context(), c)
		if err == nil {
			t.Fatalf("%s: want an error", tc.name)
		}
		texts = append(texts, err.Error())
	}
	_, err := New(Config{BaseURL: "ftp://x", TokenID: testTokenID, Secret: testSecret})
	texts = append(texts, err.Error())
	cfg := Config{BaseURL: "https://127.0.0.1:8006", TokenID: testTokenID, Secret: testSecret}
	texts = append(texts, fmt.Sprintf("%v %+v %#v %s", cfg, cfg, cfg, cfg.Secret))
	log.InfoContext(t.Context(), "config", slog.Any("config", cfg), slog.Any("secret", cfg.Secret))
	if logs.Len() == 0 || !strings.Contains(logs.String(), "pve call retried") {
		t.Fatalf("no retry was logged: %q", logs.String())
	}
	texts = append(texts, logs.String())
	for _, s := range texts {
		if strings.Contains(s, testSecret) {
			t.Errorf("secret in %q", s)
		}
	}
}

func TestWaitTask(t *testing.T) {
	task := Task{Node: "pve1", UPID: "UPID:pve1:00000001:00000002:6720F00D:qmstart:100:vws@pve!region:"}
	serve := func(polls *atomic.Int32, final string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			if polls.Add(1) < 3 {
				fmt.Fprint(w, `{"data":{"status":"running"}}`)
				return
			}
			fmt.Fprintf(w, `{"data":%s}`, final)
		}
	}
	t.Run("stopped OK succeeds", func(t *testing.T) {
		var polls atomic.Int32
		c, _ := newClient(t, serve(&polls, `{"status":"stopped","exitstatus":"OK"}`), nil)
		if err := c.WaitTask(t.Context(), task, StartWait); err != nil {
			t.Fatal(err)
		}
		if got := polls.Load(); got != 3 {
			t.Errorf("%d polls, want 3", got)
		}
	})
	t.Run("stopped with another exitstatus fails", func(t *testing.T) {
		var polls atomic.Int32
		c, _ := newClient(t, serve(&polls, `{"status":"stopped","exitstatus":"storage full"}`), nil)
		err := c.WaitTask(t.Context(), task, StartWait)
		te, ok := errors.AsType[*TaskError](err)
		if !ok || te.ExitStatus != "storage full" || te.UPID != task.UPID {
			t.Fatalf("err = %v, want a TaskError storage full", err)
		}
	})
	t.Run("a task that never stops ends at the limit on the clock", func(t *testing.T) {
		var polls atomic.Int32
		c, _ := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
			polls.Add(1)
			fmt.Fprint(w, `{"data":{"status":"running"}}`)
		}, nil)
		c.poll = time.Second
		start := c.clock.Now()
		began := time.Now()
		err := c.WaitTask(t.Context(), task, StartWait)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want DeadlineExceeded", err)
		}
		if waited := c.clock.Now().Sub(start); waited != StartWait {
			t.Errorf("clock moved %v when the wait ended, want exactly the limit %v", waited, StartWait)
		}
		// 2m of 0.8s to 1.2s waits, plus the read at the start and at the limit.
		if got := polls.Load(); got < 101 || got > 152 {
			t.Errorf("%d polls, want 101 to 152", got)
		}
		if took := time.Since(began); took > 2*time.Second {
			t.Errorf("a %v wait took %v of real time, want under 2s", StartWait, took)
		}
	})
}

func TestBadNamesNeverReachPVE(t *testing.T) {
	var requests atomic.Int32
	c, _ := newClient(t, func(http.ResponseWriter, *http.Request) { requests.Add(1) }, nil)
	ctx := t.Context()
	for name, err := range map[string]error{
		"dot-dot node":  second(c.Network(ctx, "..")),
		"slash node":    second(c.StorageContent(ctx, "pve1/../../access", "local")),
		"escaped vnet":  second(c.SDNSubnets(ctx, "v1%2F..")),
		"empty group":   second(c.FirewallGroupRules(ctx, "")),
		"zero vmid":     second(c.VMConfig(ctx, VM{Node: "pve1"})),
		"query in upid": c.WaitTask(ctx, Task{Node: "pve1", UPID: "UPID?x=1"}, StartWait),
	} {
		if err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("%d requests reached PVE", n)
	}
}

func second[T any](_ T, err error) error { return err }

func TestNewRefusesBadConfig(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no scheme":     {BaseURL: "127.0.0.1:8006", TokenID: testTokenID, Secret: testSecret},
		"no host":       {BaseURL: "https://", TokenID: testTokenID, Secret: testSecret},
		"token no name": {BaseURL: "https://h:8006", TokenID: "vws@pve", Secret: testSecret},
		"token no user": {BaseURL: "https://h:8006", TokenID: "!region", Secret: testSecret},
		"no secret":     {BaseURL: "https://h:8006", TokenID: testTokenID},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
