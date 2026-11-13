package proxmox

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func mutationScenario() pvefake.Scenario {
	s := inventoryScenario()
	s.VMs[0].Config["scsi0"] = "local:vm-100-disk-0,serial=0123456789abcdef0"
	s.VMs[0].Snapshots = []pvefake.Snapshot{{Name: "daily"}}
	s.Storages[0].Content = []pvefake.StorageContent{{
		VolID: "local:vm-100-disk-0", Content: "images", Size: 8 << 30, VMID: 100,
	}}
	return s
}

func assertMutationNotFound(t *testing.T, err error, kind resource.Kind, id string) {
	t.Helper()
	var got *resource.Error
	want := resource.NotFound(kind, id)
	if !errors.As(err, &got) || got.Code != want.Code || got.Kind != want.Kind || got.Message != want.Message {
		t.Fatalf("got %v; want %+v", err, want)
	}
}

func TestMutationGuardsStayInPool(t *testing.T) {
	for _, holder := range []bool{false, true} {
		t.Run(map[bool]string{false: "instance", true: "holder"}[holder], func(t *testing.T) {
			s := mutationScenario()
			s.Pools = append(s.Pools, "managed")
			if holder {
				s.VMs[0].Tags = "vws.holder"
			}
			b, f := networkBackend(t, s, RegionConfig{Pools: map[string]string{"123456789012": "managed"}})
			ids, _ := NewIDs("test")
			uuid := option(s.VMs[0].Config["smbios1"], "uuid")
			iid, _, _ := ids.Instance(VM{UUID: uuid})
			vid, _, _ := ids.Volume("0123456789abcdef0", "", "")
			sid, _ := ids.Snapshot(uuid, "daily")
			for _, pool := range []string{"managed", "999999999999", "managed"} {
				if err := f.MoveVM(100, pool); err != nil {
					t.Fatal(err)
				}
				before := len(f.Requests())
				vm, vmErr := b.vmForMutation(t.Context(), inventoryScope(), iid)
				vol, volErr := b.volumeForMutation(t.Context(), inventoryScope(), vid)
				snap, snapErr := b.snapshotForMutation(t.Context(), inventoryScope(), sid)
				if pool != "managed" {
					assertMutationNotFound(t, vmErr, resource.KindInstance, iid.String())
					assertMutationNotFound(t, volErr, resource.KindVolume, vid.String())
					assertMutationNotFound(t, snapErr, resource.KindSnapshot, sid.String())
				} else {
					if holder {
						assertMutationNotFound(t, vmErr, resource.KindInstance, iid.String())
					} else if vmErr != nil || vm.VMID != 100 {
						t.Fatalf("VM=%+v error=%v", vm, vmErr)
					}
					if volErr != nil || snapErr != nil || vol.ID != vid || snap.ID != sid ||
						vol.InstanceID.IsZero() != holder {
						t.Fatalf("volume=%+v %v snapshot=%+v %v", vol, volErr, snap, snapErr)
					}
				}
				reads := 0
				for _, request := range f.Requests()[before:] {
					if !strings.HasPrefix(request, http.MethodGet+" ") {
						t.Errorf("guard wrote PVE: %s", request)
					}
					if strings.Contains(request, "/cluster/resources?type=vm") {
						reads++
					}
				}
				if reads < 3 {
					t.Fatalf("guards did not each refresh VM inventory: %d", reads)
				}
			}
		})
	}
}

func TestMutationVMTemplatesAndFallbackIDs(t *testing.T) {
	for _, template := range []bool{false, true} {
		for _, meta := range []string{"", "ctime=1700000000"} {
			s := inventoryScenario()
			s.VMs[0].Template = template
			s.VMs[0].Config = map[string]string{"meta": meta}
			b, _ := networkBackend(t, s, RegionConfig{})
			ids, _ := NewIDs("test")
			id, _, _ := ids.Instance(VM{VMID: 100, Ctime: option(meta, "ctime")})
			vm, err := b.vmForMutation(t.Context(), inventoryScope(), id)
			if template {
				assertMutationNotFound(t, err, resource.KindInstance, id.String())
			} else if err != nil || vm.VMID != 100 {
				t.Fatalf("fallback VM=%+v error=%v", vm, err)
			}
		}
	}
}

func TestMutationPoolExists(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		pool := "123456789012"
		cfg := RegionConfig{}
		if mapped {
			pool = "managed"
			cfg.Pools = map[string]string{"123456789012": pool}
		}
		for _, exists := range []bool{false, true} {
			s := inventoryScenario()
			s.VMs = nil
			if exists {
				s.Pools = []string{pool}
			}
			b, f := networkBackend(t, s, RegionConfig{})
			// Exercise the live mutation guard independently of startup admission.
			b.cfg = cfg
			for range 2 {
				got, err := b.poolForMutation(t.Context(), inventoryScope())
				if exists {
					if err != nil || got != pool {
						t.Fatalf("pool=%q error=%v", got, err)
					}
				} else if got != "" || resource.CodeOf(err) != resource.CodePermissionDenied {
					t.Fatalf("missing pool=%q error=%v", got, err)
				}
			}
			if got := f.Requests(); !strings.HasSuffix(got[len(got)-1], "/pools/"+pool) {
				t.Fatalf("pool not checked live: %v", got)
			}
		}
	}
}

func TestMutationGuardsReadFailures(t *testing.T) {
	s := mutationScenario()
	s.Tokens[0].Secret = "test-secret"
	_, f := serve(t, s)
	c := startupClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/cluster/resources") || strings.Contains(r.URL.Path, "/pools/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.ServeHTTP(w, r)
	})
	b, err := New(t.Context(), c, registration(), RegionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := NewIDs("test")
	vid, _, _ := ids.Volume("0123456789abcdef0", "", "")
	sid, _ := ids.Snapshot(option(s.VMs[0].Config["smbios1"], "uuid"), "daily")
	for _, run := range []func() error{
		func() error {
			_, err := b.vmForMutation(t.Context(), inventoryScope(), resource.InstanceID{})
			return err
		},
		func() error {
			_, err := b.volumeForMutation(t.Context(), inventoryScope(), vid)
			return err
		},
		func() error {
			_, err := b.snapshotForMutation(t.Context(), inventoryScope(), sid)
			return err
		},
		func() error {
			_, err := b.poolForMutation(t.Context(), inventoryScope())
			return err
		},
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("read failure was lost: %v", err)
		}
	}
}

func TestMutationGuardSkipsUnreadableAndInvalidPoolVMs(t *testing.T) {
	s := mutationScenario()
	s.Tokens[0].Secret = "test-secret"
	target := s.VMs[0]
	target.VMID = 102
	unreadable := pvefake.VM{
		VMID: 100, Node: "pve1", Name: "offline", Pool: target.Pool, Status: "running",
		Config: map[string]string{"smbios1": "uuid=0b8f0c52-6a43-4d7e-9f0b-5f1c2d3e4a50"},
	}
	malformed := pvefake.VM{
		VMID: 101, Node: "pve1", Name: "malformed", Pool: target.Pool, Status: "running",
		Config: map[string]string{"smbios1": "uuid=not-a-uuid"},
	}
	s.VMs = []pvefake.VM{unreadable, malformed, target}
	_, f := serve(t, s)
	c := startupClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/qemu/100/config") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		f.ServeHTTP(w, r)
	})
	b, err := New(t.Context(), c, registration(), RegionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := NewIDs("test")
	id, _, _ := ids.Instance(VM{UUID: option(target.Config["smbios1"], "uuid")})
	if vm, err := b.vmForMutation(t.Context(), inventoryScope(), id); err != nil || vm.VMID != 102 {
		t.Fatalf("one bad pool VM blocked the guard: VM=%+v error=%v", vm, err)
	}
}

func TestMutationGuardDefaultProjectPoolVisibility(t *testing.T) {
	s := inventoryScenario()
	s.VMs[0].Pool = ""
	ids, _ := NewIDs("test")
	id, _, _ := ids.Instance(VM{UUID: option(s.VMs[0].Config["smbios1"], "uuid")})
	cfg := RegionConfig{DefaultProject: "123456789012"}
	b, _ := networkBackend(t, s, cfg)
	if vm, err := b.vmForMutation(t.Context(), inventoryScope(), id); err != nil || vm.VMID != 100 {
		t.Fatalf("default project's unpooled VM=%+v error=%v", vm, err)
	}
	s.Roles[0].Privs = slices.DeleteFunc(s.Roles[0].Privs, func(priv string) bool { return priv == "Pool.Audit" })
	limited, _ := networkBackend(t, s, cfg)
	_, err := limited.vmForMutation(t.Context(), inventoryScope(), id)
	if resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Fatalf("hidden pool names must refuse mutation: %v", err)
	}
}
