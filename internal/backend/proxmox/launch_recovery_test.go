package proxmox

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestLaunchRecoveryInputBounds(t *testing.T) {
	b, f := powerBackend(t, mutationScenario())
	before := len(f.Requests())
	for _, key := range []string{"", "a", strings.Repeat("a", 23), strings.Repeat("a", 63), strings.Repeat("A", 64)} {
		_, err := b.RecoverLaunch(t.Context(), inventoryScope(), key, strings.Repeat("f", 64))
		if !errors.Is(err, ErrInput) {
			t.Fatalf("key %q = %v", key, err)
		}
	}
	if len(f.Requests()) != before {
		t.Fatal("invalid input reached PVE")
	}
}

func TestLaunchRecoverySkipsUnrelatedMarkers(t *testing.T) {
	m := launchMarker(t)
	description, err := WithLaunchMarker("", m)
	if err != nil {
		t.Fatal(err)
	}
	for _, unrelated := range []string{"vws:v=broken", "vws:v=1 key=" + strings.Repeat("b", 64) + " invalid"} {
		s := mutationScenario()
		s.VMs[0].Config["description"] = description
		s.VMs = append(s.VMs, pvefake.VM{
			VMID: 101, Node: "pve1", Pool: "123456789012", Config: map[string]string{"description": unrelated},
		})
		b, _ := powerBackend(t, s)
		recovered, err := b.RecoverLaunch(t.Context(), inventoryScope(), m.Key, m.Fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		b, err = New(t.Context(), b.client, Identity(b), b.cfg)
		if err != nil {
			t.Fatal(err)
		}
		op, err := b.GetOperation(t.Context(), inventoryScope(), recovered.Operation.ID)
		if err != nil || !reflect.DeepEqual(op, recovered.Operation) {
			t.Fatalf("unrelated marker hid operation: %+v, %v", op, err)
		}
	}
}

func TestLaunchRecoveryConfigConcurrency(t *testing.T) {
	s := mutationScenario()
	m := launchMarker(t)
	description, err := WithLaunchMarker("", m)
	if err != nil {
		t.Fatal(err)
	}
	s.VMs[0].Config["description"] = description
	for i := range 19 {
		s.VMs = append(s.VMs, pvefake.VM{VMID: 101 + i, Node: "pve1", Pool: "123456789012"})
	}
	b, f := powerBackend(t, s)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	var active, maximum atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/config") {
			n := active.Add(1)
			defer active.Add(-1)
			for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
			}
			if n == 8 && maximum.Load() == 8 {
				select {
				case <-release:
				default:
					close(release)
				}
			}
			select {
			case <-release:
			case <-ctx.Done():
				return
			}
		}
		f.ServeHTTP(w, r)
	}))
	defer srv.Close()
	c, err := pveclient.New(pveclient.Config{
		BaseURL: srv.URL, TokenID: s.Tokens[0].ID, Secret: pveclient.Secret(s.Tokens[0].Secret), HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err = New(ctx, c, Identity(b), b.cfg)
	if err != nil {
		t.Fatal(err)
	}
	op, _ := newLaunchOperation("test", m.Key)
	id, _ := op.encode()
	if _, err := b.GetOperation(ctx, inventoryScope(), id); err != nil {
		t.Fatal(err)
	}
	if maximum.Load() != 8 {
		t.Fatalf("concurrent reads = %d; want 8", maximum.Load())
	}
}

func TestLaunchRecoveryRestartAndStatus(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
		rows  int
		tags  bool
		lock  string
		fail  bool
		state resource.OperationState
	}{
		{"partial", 2, 1, false, "clone", false, resource.OperationRunning},
		{"partial finalized", 2, 1, true, "", false, resource.OperationRunning},
		{"unlocked", 2, 2, false, "", false, resource.OperationRunning},
		{"locked finalized tags", 2, 2, true, "clone", false, resource.OperationRunning},
		{"complete", 2, 2, true, "", false, resource.OperationSucceeded},
		{"failed", 2, 1, false, "", true, resource.OperationFailed},
		{"failed after tags", 2, 2, true, "", true, resource.OperationFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := mutationScenario()
			base := s.VMs[0]
			s.VMs = nil
			m := launchMarker(t)
			m.Count = tc.count
			reservation, err := newIDs(t, "test").Reservation(m.Key)
			if err != nil {
				t.Fatal(err)
			}
			for i := range tc.rows {
				m.Index, m.UUID = i, fmt.Sprintf("5f0c3e9a-8b5d-4b8e-9a51-%012x", i+1)
				description, err := WithLaunchMarker("operator text", m)
				if err != nil {
					t.Fatal(err)
				}
				vm := base
				vm.VMID = 100 + i
				vm.Config = map[string]string{"description": description, "lock": tc.lock, "smbios1": "uuid=" + m.UUID}
				if !tc.tags {
					// PVE generates a different UUID before finalize, even after unlock.
					vm.Config["smbios1"] = "uuid=00000000-0000-4000-8000-000000000100"
				} else {
					tags, err := LaunchMarkerTags(m, reservation)
					if err != nil {
						t.Fatal(err)
					}
					vm.Tags = strings.Join(tags, ";")
				}
				if tc.fail {
					vm.Tags += ";" + LaunchFailureTag
				}
				s.VMs = append(s.VMs, vm)
			}
			b, f := powerBackend(t, s)
			first, err := b.RecoverLaunch(t.Context(), inventoryScope(), m.Key, m.Fingerprint)
			if err != nil || first.Count != tc.count || len(first.Instances) != tc.rows || first.Reservation != reservation {
				t.Fatalf("recover = %+v, %v", first, err)
			}
			for range 2 {
				b, err = New(t.Context(), b.client, Identity(b), b.cfg)
				if err != nil {
					t.Fatal(err)
				}
				got, err := b.RecoverLaunch(t.Context(), inventoryScope(), m.Key, m.Fingerprint)
				if err != nil || !reflect.DeepEqual(got, first) {
					t.Fatalf("replay = %+v, %v; want %+v", got, err, first)
				}
				op, err := b.GetOperation(t.Context(), inventoryScope(), first.Operation.ID)
				if err != nil || !reflect.DeepEqual(op, first.Operation) || op.State != tc.state {
					t.Fatalf("status = %+v, %v; want %s", op, err, tc.state)
				}
				_, err = b.RecoverLaunch(t.Context(), inventoryScope(), m.Key, m.Fingerprint[:63]+"0")
				if resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
					t.Fatalf("mismatch = %v", err)
				}
				_, err = b.RecoverLaunch(t.Context(), inventoryScope(), m.Key[:63]+"0", m.Fingerprint)
				if resource.CodeOf(err) != resource.CodeNotFound {
					t.Fatalf("same prefix, other key = %v", err)
				}
			}
			for i := range tc.rows {
				want, _, err := newIDs(t, "test").Instance(VM{UUID: fmt.Sprintf("5f0c3e9a-8b5d-4b8e-9a51-%012x", i+1)})
				if err != nil || first.Instances[i] != want {
					t.Fatalf("index %d = %s; want %s: %v", i, first.Instances[i], want, err)
				}
				if err := f.MoveVM(100+i, "managed"); err != nil {
					t.Fatal(err)
				}
			}
			_, err = b.RecoverLaunch(t.Context(), inventoryScope(), m.Key, m.Fingerprint)
			if resource.CodeOf(err) != resource.CodeNotFound {
				t.Fatalf("foreign recovery = %v", err)
			}
			_, err = b.GetOperation(t.Context(), inventoryScope(), first.Operation.ID)
			if resource.CodeOf(err) != resource.CodeNotFound {
				t.Fatalf("foreign operation = %v", err)
			}
			bound := inventoryScope()
			bound.Pool = "managed"
			got, err := b.RecoverLaunch(t.Context(), bound, m.Key, m.Fingerprint)
			if err != nil || !reflect.DeepEqual(got, first) {
				t.Fatalf("bound pool replay = %+v, %v", got, err)
			}
			op, err := b.GetOperation(t.Context(), bound, first.Operation.ID)
			if err != nil || !reflect.DeepEqual(op, first.Operation) {
				t.Fatalf("bound pool operation = %+v, %v", op, err)
			}
			if len(f.PoolWriteViolations()) != 0 {
				t.Fatal(f.PoolWriteViolations())
			}
		})
	}
}

func TestLaunchRecoveryRefusesAmbiguousMarkers(t *testing.T) {
	for _, corrupt := range []string{"duplicate index", "count", "fingerprint", "malformed"} {
		t.Run(corrupt, func(t *testing.T) {
			s := mutationScenario()
			m := launchMarker(t)
			m.Count = 2
			first, _ := WithLaunchMarker("", m)
			if corrupt == "count" {
				m.Count = 3
			}
			if corrupt == "fingerprint" {
				m.Fingerprint = strings.Repeat("b", 64)
			}
			second, _ := WithLaunchMarker("", m)
			if corrupt == "malformed" {
				second += " invalid"
			}
			s.VMs = []pvefake.VM{
				{VMID: 100, Node: "pve1", Pool: "123456789012", Config: map[string]string{"description": first}},
				{VMID: 101, Node: "pve1", Pool: "123456789012", Config: map[string]string{"description": second}},
			}
			b, _ := powerBackend(t, s)
			op, _ := newLaunchOperation("test", m.Key)
			id, _ := op.encode()
			_, err := b.GetOperation(t.Context(), inventoryScope(), id)
			if resource.CodeOf(err) != resource.CodeUnavailable {
				t.Fatalf("corrupt recovery = %v", err)
			}
		})
	}
}
