package proxmox

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func phase2World(t *testing.T, broken string) backendtest.MutationWorld {
	t.Helper()
	w, m, req := finalizeBackend(t)
	req.Count = 3
	connect := func() backend.Set {
		old := w.b
		b, err := New(t.Context(), old.client, Identity(old), old.cfg)
		checkLaunch(t, err)
		if b == old {
			t.Fatal("restart reused the old backend")
		}
		w.b = b
		set := b.Set()
		if broken == "pool" {
			set.Compute = phase2Compute{Compute: set.Compute, unguarded: b, target: func() tagWriteTarget {
				return tagWriteTarget{vm: launchVM(t, w, 0)}
			}}
		}
		return set
	}
	return backendtest.MutationWorld{
		Connect: connect, Mutation: m, Launch: req, OtherPool: "images",
		Finalize: func() error { return w.b.FinalizeLaunches(t.Context(), admitFinalize) },
		Calls:    func() int { return len(w.f.Requests()) },
		Writes: func() int {
			return len(slices.DeleteFunc(w.f.RequestMethods(), func(method string) bool { return method == "GET" }))
		},
		Interrupt: func(window string) []resource.InstanceID {
			if window == "W2" {
				w.failAt = 3
				if _, err := w.b.Set().Compute.RunInstances(t.Context(), m, req); err == nil {
					t.Fatal("partial clone failure was ignored")
				}
				partial, err := w.b.RecoverLaunch(t.Context(), m.Scope, m.Key, m.Fingerprint)
				checkLaunch(t, err)
				return slices.SortedFunc(maps.Values(partial.Instances),
					func(a, b resource.InstanceID) int { return strings.Compare(a.String(), b.String()) })
			}
			got, err := w.b.Set().Compute.RunInstances(t.Context(), m, req)
			checkLaunch(t, err)
			if window == "W4" {
				w.f.FailNext("qmstart", "contract interrupted before start")
				if err := w.b.FinalizeLaunches(t.Context(), admitFinalize); err == nil {
					t.Fatal("start failure was ignored")
				}
				cfg, err := w.b.client.VMConfig(t.Context(), launchVM(t, w, 0))
				checkLaunch(t, err)
				marker, found, err := ReadLaunchMarker(cfg.Description)
				if err != nil || !found || configUUID(cfg) != marker.UUID || strings.Contains(cfg.Tags, "vws.k.") {
					t.Fatalf("W4 did not reach configured, unfinalized VM: %+v, %v", cfg, err)
				}
			}
			ids := make([]resource.InstanceID, len(got.Items))
			for i, item := range got.Items {
				ids[i] = item.ID
			}
			return ids
		},
		Denied: func(state string) backend.Set {
			fs := w.f.PMXCFS()
			for _, dir := range []string{
				"/etc/pve/vws", "/etc/pve/priv", "/etc/pve/priv/lock", "/etc/pve/priv/lock/vws-region",
			} {
				checkLaunch(t, fs.Mkdir(dir))
			}
			leader, err := NewLeader(t.Context(), w.b, leaseHelper{fs}, leaderPath)
			checkLaunch(t, err)
			clock := &leaseClock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
			leader.now, leader.read = clock.now, fs.ReadFile
			acquireLeader(t, leader)
			if state == "quorum" {
				w.f.SetQuorate(false)
				leader.checkQuorum(t.Context())
			} else {
				clock.advance(21 * time.Second)
				leader.checkQuorum(t.Context())
			}
			set := w.b.Set()
			if broken != "quorum" {
				set.Compute = phase2Compute{Compute: set.Compute, admit: leader.Admit}
			}
			return set
		},
		CheckTask: func(id resource.OperationID, iid resource.InstanceID) error {
			decoded, err := decodeOperation(id)
			if err != nil {
				return fmt.Errorf("decode task operation %s: %w", id, err)
			}
			task, ok := decoded.(taskOperation)
			if !ok || task.instance != iid || task.action != resource.ActionStopInstances {
				return fmt.Errorf("task operation %s has wrong identity: %+v", id, decoded)
			}
			rows, err := w.b.client.OwnTasks(t.Context(), "pve1", url.Values{"typefilter": {"qmstop"}})
			if err != nil {
				return fmt.Errorf("list stop UPIDs: %w", err)
			}
			for _, row := range rows {
				if task.node == nodeHash(row.Node) && task.pid == row.PID && task.starttime == row.StartTime {
					encoded, err := task.encode()
					if err != nil {
						return fmt.Errorf("encode UPID %s: %w", row.UPID, err)
					}
					if encoded != id || row.UPID == "" || row.Status != "OK" {
						return fmt.Errorf("UPID %s round trip: encoded %s, status %s",
							row.UPID, encoded, row.Status)
					}
					return nil
				}
			}
			return fmt.Errorf("operation %s has no matching UPID in %+v", id, rows)
		},
	}
}

// Only the exercised mutation needs wrapping: the production region layer
// calls this same Admit method before dispatch, outside backend.Set.
type phase2Compute struct {
	backend.Compute
	admit     func(context.Context) (string, error)
	unguarded *Backend
	target    func() tagWriteTarget
}

func (c phase2Compute) CreateTags(
	ctx context.Context, m backend.Mutation, req resource.CreateTagsRequest,
) (resource.Accepted[resource.Instance], error) {
	if c.admit != nil {
		if _, err := c.admit(ctx); err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
	}
	if c.unguarded != nil {
		target := c.target()
		target.ref = req.IDs[0].Ref()
		op, err := c.unguarded.writeResourceTags(ctx, m.Scope, m.Key,
			[]tagWriteTarget{target}, req.Tags, nil)
		return resource.Accepted[resource.Instance]{Operation: op}, err
	}
	return c.Compute.CreateTags(ctx, m, req)
}

func runPhase2Contract(t *testing.T, broken string) {
	t.Helper()
	w := phase2World(t, "")
	set := w.Connect()
	b, ok := set.Compute.(*Backend)
	if !ok {
		t.Fatal("writable harness did not construct a Backend")
	}
	caps, err := b.RegionCapabilities(t.Context(), b.region)
	checkLaunch(t, err)
	backendtest.Run(t, w.Connect, caps, backendtest.Phase2(func(t *testing.T) backendtest.MutationWorld {
		return phase2World(t, broken)
	}))
}

func TestContractPhase2(t *testing.T) {
	runPhase2Contract(t, "")
}

func TestPhase2GuardProbe(t *testing.T) {
	if broken := os.Getenv("VWS_PHASE2_BROKEN_GUARD"); broken != "" {
		runPhase2Contract(t, broken)
	}
}

func TestPhase2GuardRemoval(t *testing.T) {
	for _, tc := range []struct{ guard, group, diagnostic string }{
		{"pool", "PoolTenancy", "foreign pool mutation"},
		{"quorum", "NoQuorum", "quorum admission reached PVE or succeeded"},
	} {
		t.Run(tc.guard, func(t *testing.T) {
			executable, err := os.Executable()
			checkLaunch(t, err)
			cmd := exec.CommandContext(t.Context(), executable,
				"-test.run=^TestPhase2GuardProbe$/^Phase2$/^"+tc.group+"$", "-test.v")
			cmd.Env = append(os.Environ(), "VWS_PHASE2_BROKEN_GUARD="+tc.guard)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 ||
				!strings.Contains(string(out), tc.diagnostic) || strings.Contains(string(out), "--- SKIP") {
				t.Fatalf("guard removal did not fail its contract group: %v\n%s", err, out)
			}
			t.Logf("removed %s guard: contract group failed as required\n%s", tc.guard, out)
		})
	}
}
