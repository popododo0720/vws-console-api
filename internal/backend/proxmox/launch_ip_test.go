package proxmox

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func staticLaunchBackend(t *testing.T) (*launchWorld, backend.Mutation, resource.RunInstancesRequest) {
	t.Helper()
	w, m, req := finalizeBackend(t)
	w.b.cfg.Subnets = map[string]SubnetConfig{"vmbr0": {
		CIDR: "192.0.2.0/24", Gateway: "192.0.2.1", IPRange: "192.0.2.2-192.0.2.10",
	}}
	return w, m, req
}

func setLaunchIP(t *testing.T, w *launchWorld, vm pveclient.VM, ip string) {
	t.Helper()
	cfg, err := w.b.client.VMConfig(t.Context(), vm)
	checkLaunch(t, err)
	checkLaunch(t, w.b.client.WriteConfig(t.Context(), vm, cfg.Digest, url.Values{"ipconfig0": {ip}}))
}

func TestStaticLaunchLowestFreeAndModes(t *testing.T) {
	for _, mode := range []string{"", "static", "direct", "dhcp"} {
		t.Run(mode, func(t *testing.T) {
			w, m, req := staticLaunchBackend(t)
			subnet := w.b.cfg.Subnets["vmbr0"]
			subnet.Mode, subnet.IPRange = mode, ""
			w.b.cfg.Subnets["vmbr0"] = subnet
			setLaunchIP(t, w, pveclient.VM{Node: "pve1", VMID: 100}, "ip=192.0.2.2/24,gw=192.0.2.1")
			_, err := w.b.RunInstances(t.Context(), m, req)
			checkLaunch(t, err)
			checkLaunch(t, w.b.FinalizeLaunches(t.Context(), admitFinalize))
			for i := range req.Count {
				cfg, err := w.b.client.VMConfig(t.Context(), launchVM(t, w, i))
				checkLaunch(t, err)
				want := "ip=192.0.2.2/24,gw=192.0.2.1"
				if mode == "" || mode == "static" {
					want = fmt.Sprintf("ip=192.0.2.%d/24,gw=192.0.2.1", i+3)
				}
				if cfg.IPConfig0 != want {
					t.Fatalf("mode %q VM %d: %q, want %q", mode, i, cfg.IPConfig0, want)
				}
			}
			doc, err := w.b.RegionCapabilities(t.Context(), w.b.region)
			checkLaunch(t, err)
			if doc.Features.PrivateIPMode != "static" || strings.Contains(doc.Actions["ec2:RunInstances"].Reason, "static IPs") {
				t.Fatalf("static capability missing: %+v", doc)
			}
		})
	}
}

func TestStaticLaunchExhaustionAndPending(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprint(pending), func(t *testing.T) {
			w, m, req := staticLaunchBackend(t)
			subnet := w.b.cfg.Subnets["vmbr0"]
			subnet.IPRange = "192.0.2.2-192.0.2.2"
			w.b.cfg.Subnets["vmbr0"], req.Count = subnet, 1
			if pending {
				_, err := w.b.RunInstances(t.Context(), m, req)
				checkLaunch(t, err)
				m.Key = strings.Repeat("b", 64)
			} else {
				setLaunchIP(t, w, pveclient.VM{Node: "pve1", VMID: 100}, "ip=192.0.2.2/24")
			}
			before := len(w.forms)
			_, err := w.b.RunInstances(t.Context(), m, req)
			if !resource.IsInsufficientFreeAddressesInSubnet(resource.AsError(err)) || len(w.forms) != before {
				t.Fatalf("exhaustion cloned a VM or wrong error: %v clones=%d", err, len(w.forms))
			}
		})
	}
}

func TestStaticLaunchConcurrentAndCrashRetry(t *testing.T) {
	w, m, req := staticLaunchBackend(t)
	req.Count = 1
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, key := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		wg.Go(func() {
			<-start
			mutation := m
			mutation.Key = key
			_, err := w.b.RunInstances(t.Context(), mutation, req)
			if err != nil {
				t.Error(err)
			}
		})
	}
	close(start)
	wg.Wait()
	crashed := false
	w.intercept = func(rw http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut && r.ParseForm() == nil && r.Form.Has("ipconfig0") {
			crashed = true
			rw.WriteHeader(http.StatusServiceUnavailable)
			_, _ = rw.Write([]byte(`{"message":"crash before config commit"}`))
			return true
		}
		return false
	}
	if err := w.b.FinalizeLaunches(t.Context(), admitFinalize); err == nil || !crashed {
		t.Fatalf("did not interrupt between address choice and write: %v", err)
	}
	w.intercept = nil
	var err error
	w.b, err = New(t.Context(), w.b.client, Identity(w.b), w.b.cfg)
	checkLaunch(t, err)
	_, err = w.b.RunInstances(t.Context(), m, req)
	checkLaunch(t, err)
	if len(w.forms) != 2 {
		t.Fatalf("retry cloned %d VMs", len(w.forms))
	}
	w.f.FailNext("qmstart", "crash after config commit")
	if err := w.b.FinalizeLaunches(t.Context(), admitFinalize); err == nil {
		t.Fatal("start failure was ignored")
	}
	checkLaunch(t, w.b.FinalizeLaunches(t.Context(), admitFinalize))
	ips := map[string]bool{}
	for i := range 2 {
		cfg, err := w.b.client.VMConfig(t.Context(), launchVM(t, w, i))
		checkLaunch(t, err)
		ips[privateIP(cfg.IPConfig0).String()] = true
	}
	if !reflect.DeepEqual(ips, map[string]bool{"192.0.2.2": true, "192.0.2.3": true}) {
		t.Fatalf("duplicate or missing addresses: %v", ips)
	}
}

func TestStaticLaunchRefusesIncompleteInventory(t *testing.T) {
	for _, failure := range []string{"permissions", "config", "locked", "filled after acceptance"} {
		t.Run(failure, func(t *testing.T) {
			w, m, req := staticLaunchBackend(t)
			req.Count = 1
			subnet := w.b.cfg.Subnets["vmbr0"]
			subnet.IPRange = "192.0.2.2-192.0.2.2"
			w.b.cfg.Subnets["vmbr0"] = subnet
			_, err := w.b.RunInstances(t.Context(), m, req)
			checkLaunch(t, err)
			if failure == "filled after acceptance" {
				setLaunchIP(t, w, pveclient.VM{Node: "pve1", VMID: 100}, "ip=192.0.2.2/24")
			}
			w.intercept = func(rw http.ResponseWriter, r *http.Request) bool {
				switch {
				case failure == "permissions" && strings.HasSuffix(r.URL.Path, "/access/permissions"):
					_, _ = rw.Write([]byte(`{"data":{"/vms":{"VM.Audit":0}}}`))
					return true
				case failure == "config" && strings.HasSuffix(r.URL.Path, "/qemu/100/config"):
					rw.WriteHeader(http.StatusForbidden)
					_, _ = rw.Write([]byte(`{"message":"unreadable"}`))
					return true
				case failure == "locked" && r.Method == http.MethodGet &&
					strings.HasSuffix(r.URL.Path, fmt.Sprintf("/qemu/%d/config", launchVM(t, w, 0).VMID)):
					_, _ = fmt.Fprintf(rw, `{"data":{"description":%q,"lock":"clone"}}`, w.forms[0].Get("description"))
					return true
				}
				return false
			}
			if err := w.b.FinalizeLaunches(t.Context(), admitFinalize); err == nil {
				t.Fatal("allocated from incomplete or exhausted inventory")
			}
			w.intercept = nil
			cfg, err := w.b.client.VMConfig(t.Context(), launchVM(t, w, 0))
			checkLaunch(t, err)
			if cfg.IPConfig0 != "" {
				t.Fatalf("failed allocation wrote %s", cfg.IPConfig0)
			}
		})
	}
}

func TestStaticLaunchLeaderHandoverFencesDelayedWrite(t *testing.T) {
	w, m, req := staticLaunchBackend(t)
	req.Count = 1
	_, err := w.b.RunInstances(t.Context(), m, req)
	checkLaunch(t, err)
	second := m
	second.Pool, second.Key = "images", strings.Repeat("b", 64)
	_, err = w.b.RunInstances(t.Context(), second, req)
	checkLaunch(t, err)
	fs := w.f.PMXCFS()
	for _, dir := range []string{"/etc/pve/vws", "/etc/pve/priv", "/etc/pve/priv/lock", "/etc/pve/priv/lock/vws-region"} {
		checkLaunch(t, fs.Mkdir(dir))
	}
	first, err := NewLeader(t.Context(), w.b, leaseHelper{fs}, leaderPath)
	checkLaunch(t, err)
	clock := &leaseClock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	first.now, first.read = clock.now, fs.ReadFile
	acquireLeader(t, first)
	fence := func(leader *Leader) func(context.Context) error {
		return func(ctx context.Context) error {
			peer, err := leader.Admit(ctx)
			if peer != "" {
				return fmt.Errorf("not local leader")
			}
			return err
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	held, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	target := fmt.Sprintf("/qemu/%d/config", launchVM(t, w, 0).VMID)
	var once sync.Once
	w.intercept = func(_ http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, target) &&
			r.ParseForm() == nil && r.Form.Has("ipconfig0") {
			once.Do(func() {
				close(held)
				select {
				case <-release:
				case <-ctx.Done():
				}
			})
		}
		return false
	}
	oldDone := make(chan error, 1)
	go func() { oldDone <- w.b.FinalizeLaunches(ctx, fence(first)) }()
	select {
	case <-held:
	case <-ctx.Done():
		t.Fatal("old leader did not choose an address")
	}
	next := leaderFollower(t, first, "pve2", clock)
	clock.advance(21 * time.Second)
	acquireLeader(t, next)
	fresh, err := New(ctx, w.b.client, Identity(w.b), w.b.cfg)
	checkLaunch(t, err)
	// Reverse pool order so the new leader allocates another VM before the delayed target.
	fresh.cfg.Pools = map[string]string{"a": "images", "z": "managed"}
	calls := 0
	checkLaunch(t, fresh.FinalizeLaunches(ctx, func(ctx context.Context) error {
		calls++
		if calls == 4 { // Two digest barriers, then the other VM's allocation and start.
			unblock()
			select {
			case err := <-oldDone:
				if err == nil {
					t.Error("old leader completed after takeover")
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return fence(next)(ctx)
	}))
	for i, want := range []string{"192.0.2.3", "192.0.2.2"} {
		cfg, err := fresh.client.VMConfig(ctx, launchVM(t, w, i))
		checkLaunch(t, err)
		if privateIP(cfg.IPConfig0).String() != want {
			t.Fatalf("VM %d address %q, want %s", i, cfg.IPConfig0, want)
		}
	}
}

func TestStaticPrivateIPQuery(t *testing.T) {
	for _, ip := range []string{"", "ip=dhcp", "ip=192.0.2.9/24,gw=192.0.2.1"} {
		t.Run(ip, func(t *testing.T) {
			w, m, req := staticLaunchBackend(t)
			req.Count = 1
			_, err := w.b.RunInstances(t.Context(), m, req)
			checkLaunch(t, err)
			setLaunchIP(t, w, launchVM(t, w, 0), ip)
			w.b.region = resource.RegionName
			res := storageQuery(t, w.b.Set(), w.b)(url.Values{"Action": {"DescribeInstances"}})
			var result struct {
				Items []struct {
					IP  string `xml:"privateIpAddress"`
					NIC []struct {
						IP string `xml:"privateIpAddress"`
					} `xml:"networkInterfaceSet>item"`
				} `xml:"reservationSet>item>instancesSet>item"`
			}
			checkLaunch(t, xml.Unmarshal(res.Body.Bytes(), &result))
			want := ""
			if ip != "" && ip != "ip=dhcp" {
				want = "192.0.2.9"
			}
			if res.Code != 200 || len(result.Items) != 1 || result.Items[0].IP != want ||
				len(result.Items[0].NIC) != 1 || result.Items[0].NIC[0].IP != want {
				t.Fatalf("private IP wire mismatch: %d %s", res.Code, res.Body)
			}
		})
	}
}
