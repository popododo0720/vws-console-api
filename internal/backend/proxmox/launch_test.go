package proxmox

import (
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type launchWorld struct {
	b      *Backend
	f      *pvefake.Fake
	forms  []url.Values
	failAt int
	// failConfig is a path suffix whose config reads answer 500.
	failConfig string
	elapsed    atomic.Int64
	intercept  func(http.ResponseWriter, *http.Request) bool
}

func launchBackend(
	t *testing.T, shared bool, edits ...func(*pvefake.Scenario),
) (*launchWorld, backend.Mutation, resource.RunInstancesRequest) {
	t.Helper()
	cryptotest.SetGlobalRandom(t, 771)
	s := mutationScenario()
	s.Nodes = []pvefake.Node{
		{Name: "pve1", MaxCPU: 8, MaxMem: 32 << 30},
		{Name: "pve2", MaxCPU: 8, MaxMem: 32 << 30},
	}
	s.Pools = []string{"123456789012", "managed", "images"}
	s.VMs[0].Template, s.VMs[0].Pool = true, "images"
	s.VMs[0].Tags = "public"
	s.Networks = []pvefake.Network{{Node: "pve1", Iface: "vmbr0", Type: "bridge", CIDR: "192.0.2.1/24"}}
	s.Storages[0].MaxDisk = 256 << 30
	if shared {
		s.Storages[0].Shared = 1
	}
	s.Storages = append(s.Storages, pvefake.Storage{Node: "pve2", Name: "local", MaxDisk: 256 << 30})
	s.Roles = append(s.Roles,
		pvefake.Role{ID: "Launch", Privs: []string{"VM.Clone", "VM.Allocate", "VM.Audit", "Pool.Audit"}},
		pvefake.Role{ID: "Storage", Privs: []string{"Datastore.AllocateSpace", "Datastore.Audit"}})
	for _, pool := range s.Pools {
		s.Tokens[0].ACL = append(s.Tokens[0].ACL, pvefake.ACE{Path: "/pool/" + pool, Role: "Launch"})
	}
	s.Tokens[0].ACL = append(s.Tokens[0].ACL, pvefake.ACE{Path: "/storage/local", Role: "Storage"})
	for _, edit := range edits {
		edit(&s)
	}
	w := &launchWorld{}
	f, err := pvefake.NewWithClock(s, func() time.Time {
		return time.Unix(1700000000, w.elapsed.Load())
	})
	if err != nil {
		t.Fatal(err)
	}
	w.f = f
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if w.intercept != nil && w.intercept(rw, r) {
			return
		}
		if w.failConfig != "" && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, w.failConfig) {
			rw.WriteHeader(http.StatusInternalServerError)
			_, _ = rw.Write([]byte(`{"message":"node unreachable"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/clone") {
			if err := r.ParseForm(); err != nil {
				t.Error(err)
				return
			}
			w.forms = append(w.forms, r.Form)
			if len(w.forms) == w.failAt {
				rw.WriteHeader(http.StatusInternalServerError)
				_, _ = rw.Write([]byte(`{"message":"clone rejected"}`))
				return
			}
		}
		f.ServeHTTP(rw, r)
	}))
	t.Cleanup(srv.Close)
	c, err := pveclient.New(pveclient.Config{
		BaseURL: srv.URL, TokenID: s.Tokens[0].ID,
		Secret: pveclient.Secret(s.Tokens[0].Secret), HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	w.b, err = New(t.Context(), c, registration(), RegionConfig{
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
		Storages: map[string]string{"gp2": "local"}, Templates: TemplateConfig{Pool: "images"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := newIDs(t, "test")
	image, _ := ids.Image(option(s.VMs[0].Config["smbios1"], "uuid"))
	subnet, _ := ids.BridgeSubnet("vmbr0", "192.0.2.0/24")
	m := backend.Mutation{Scope: inventoryScope(), Key: strings.Repeat("a", 64), Fingerprint: strings.Repeat("f", 64)}
	return w, m, resource.RunInstancesRequest{
		ImageID: image, SubnetID: subnet,
		InstanceType: "vws.small", Count: 2, KeyName: "launch-key", Tags: map[string]string{"Name": "web / worker"},
	}
}

func TestRunInstancesPendingUUIDs(t *testing.T) {
	w, m, req := launchBackend(t, false)
	req.Count = 10
	got, err := w.b.RunInstances(t.Context(), m, req)
	if err != nil || len(got.Items) != req.Count || len(w.forms) != req.Count {
		t.Fatalf("accepted = %+v, %v; clones=%d", got, err, len(w.forms))
	}
	for i, form := range w.forms {
		marker, found, err := ReadLaunchMarker(form.Get("description"))
		if err != nil || !found || marker.Index != i || marker.Count != req.Count || marker.KeyPair != req.KeyName {
			t.Fatalf("marker=%+v %v", marker, err)
		}
		id, _, _ := newIDs(t, "test").Instance(VM{UUID: marker.UUID})
		serial, _ := newIDs(t, "test").RootVolumeSerial(marker.UUID)
		tags, err := ReadTags(nil, form.Get("description"))
		if err != nil || !reflect.DeepEqual(tags.User, req.Tags) || marker.DOT[0] != serial[:8] ||
			got.Items[i].ID != id || got.Items[i].State != resource.InstancePending ||
			got.Items[i].OwnerID != m.Account || marker.UUID[14] != '4' {
			t.Fatalf("item=%+v marker=%+v tags=%+v error=%v", got.Items[i], marker, tags, err)
		}
		if form.Get("full") != "1" || form.Has("target") || form.Get("storage") != "local" ||
			form.Get("name") != "web---worker" {
			t.Fatalf("clone form=%v", form)
		}
	}
	op, _ := newLaunchOperation("test", m.Key)
	id, _ := op.encode()
	if got.Operation.ID != id || got.Operation.State != resource.OperationRunning {
		t.Fatalf("operation=%+v", got.Operation)
	}
	caps, err := w.b.RegionCapabilities(t.Context(), w.b.region)
	if err != nil || caps.Actions["ec2:RunInstances"].State != resource.ActionPartial {
		t.Fatalf("capability=%+v %v", caps.Actions["ec2:RunInstances"], err)
	}
}

func TestRunInstancesPoolAndTemplate(t *testing.T) {
	for _, visibility := range []string{"public pool", "public tag", "owned", "foreign"} {
		t.Run(visibility, func(t *testing.T) {
			w, m, req := launchBackend(t, false)
			m.Pool, req.Count = "managed", 1
			switch visibility {
			case "public tag":
				w.b.cfg.Templates = TemplateConfig{Tag: "public"}
			case "owned", "foreign":
				w.b.cfg.Templates = TemplateConfig{}
				pool := "managed"
				if visibility == "foreign" {
					pool = "123456789012"
				}
				if err := w.f.MoveVM(100, pool); err != nil {
					t.Fatal(err)
				}
			}
			got, err := w.b.RunInstances(t.Context(), m, req)
			if visibility == "foreign" {
				assertMutationNotFound(t, err, resource.KindImage, req.ImageID.String())
				if len(w.forms) != 0 {
					t.Fatal("foreign template was cloned")
				}
				return
			}
			if err != nil || len(got.Items) != 1 || w.forms[0].Get("pool") != "managed" {
				t.Fatalf("bound pool result=%+v %v forms=%v", got, err, w.forms)
			}
			if len(w.f.PoolWriteViolations()) != 0 {
				t.Fatal(w.f.PoolWriteViolations())
			}
		})
	}
}

func TestRunInstancesCapacityWritesNothing(t *testing.T) {
	w, m, req := launchBackend(t, false)
	w.b.cfg.Scheduler.HostReserveMiB = 32 << 10
	before := len(w.f.RequestMethods())
	_, err := w.b.RunInstances(t.Context(), m, req)
	if !resource.IsInsufficientInstanceCapacity(resource.AsError(err)) {
		t.Fatalf("capacity=%v", err)
	}
	for _, method := range w.f.RequestMethods()[before:] {
		if method != http.MethodGet {
			t.Fatalf("capacity failure wrote %s", method)
		}
	}
}

func TestRunInstancesNextIDRace(t *testing.T) {
	for _, collisions := range []int{1, 3, 4} {
		t.Run(strconv.Itoa(collisions), func(t *testing.T) {
			w, m, req := launchBackend(t, false)
			req.Count = 1
			var ids []int
			for range collisions {
				ids = append(ids, 100)
			}
			if err := w.f.SetNextIDs(append(ids, 101)...); err != nil {
				t.Fatal(err)
			}
			got, err := w.b.RunInstances(t.Context(), m, req)
			if collisions == 4 {
				if err == nil || len(w.forms) != 4 {
					t.Fatalf("retry limit=%+v %v clones=%d", got, err, len(w.forms))
				}
				return
			}
			if err != nil || len(got.Items) != 1 || len(w.forms) != collisions+1 {
				t.Fatalf("race=%+v %v clones=%d", got, err, len(w.forms))
			}
			rows, err := w.b.client.ClusterResources(t.Context(), pveclient.ResourceVM)
			if err != nil || len(rows) != 2 {
				t.Fatalf("duplicate clone rows=%+v error=%v", rows, err)
			}
		})
	}
}

func TestRunInstancesReplayRestartAndPartial(t *testing.T) {
	w, m, req := launchBackend(t, true)
	w.b.cfg.LinkedClones = true
	w.failAt = 2
	if _, err := w.b.RunInstances(t.Context(), m, req); err == nil {
		t.Fatal("injected second clone failure succeeded")
	}
	first := w.forms[0].Get("description")
	var accepted resource.Accepted[resource.Instance]
	for attempt := range 3 {
		var err error
		w.b, err = New(t.Context(), w.b.client, Identity(w.b), w.b.cfg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := w.b.RunInstances(t.Context(), m, req)
		if err != nil || len(got.Items) != 2 || len(w.forms) != 3 {
			t.Fatalf("partial replay=%+v %v clones=%d", got, err, len(w.forms))
		}
		if attempt == 0 {
			accepted = got
		} else if !reflect.DeepEqual(got, accepted) {
			t.Fatalf("restart changed result: %+v != %+v", got, accepted)
		}
	}
	marker, _, _ := ReadLaunchMarker(first)
	replayed, err := w.b.RunInstances(t.Context(), m, req)
	if err != nil || !reflect.DeepEqual(replayed, accepted) || len(w.forms) != 3 {
		t.Fatalf("same-process replay=%+v %v clones=%d", replayed, err, len(w.forms))
	}
	id, _, _ := newIDs(t, "test").Instance(VM{UUID: marker.UUID})
	if accepted.Items[0].ID != id || w.forms[2].Get("full") != "0" || !w.forms[2].Has("target") {
		t.Fatalf("partial clone=%v instances=%+v", w.forms[2], accepted.Items)
	}
	m.Fingerprint = strings.Repeat("b", 64)
	req.Count = 3
	if _, err := w.b.RunInstances(t.Context(), m, req); resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
		t.Fatalf("changed request=%v", err)
	}
	if len(w.forms) != 3 {
		t.Fatal("mismatch cloned more VMs")
	}
}

func TestRunInstancesBoundaryInputs(t *testing.T) {
	for _, field := range []string{
		"count zero", "count high", "type", "disabled type", "key", "key length",
		"tags", "tag length", "description budget", "userdata", "userdata size", "subnet", "image", "identity",
		"extra disks", "root size", "read only",
	} {
		t.Run(field, func(t *testing.T) {
			w, m, req := launchBackend(t, false)
			switch field {
			case "count zero":
				req.Count = 0
			case "count high":
				req.Count = 11
			case "type":
				req.InstanceType = "../../node"
			case "disabled type":
				w.b.cfg.InstanceTypes = map[string]InstanceTypeConfig{}
			case "key":
				req.KeyName = "key\nud=bad"
			case "key length":
				req.KeyName = strings.Repeat("x", 256)
			case "tags":
				req.Tags = map[string]string{"vws:key": "bad"}
			case "tag length":
				req.Tags = map[string]string{"x": strings.Repeat("y", 257)}
			case "description budget":
				req.Tags = map[string]string{}
				for i := range 50 {
					req.Tags[fmt.Sprintf("tag%d", i)] = strings.Repeat("x", 256)
				}
			case "userdata":
				req.UserData = "#cloud-config"
			case "userdata size":
				req.UserData = strings.Repeat("x", 32769)
			case "subnet":
				req.SubnetID = resource.SubnetID{}
			case "image":
				req.ImageID = resource.ImageID{}
			case "identity":
				m.Key = "../../key"
			case "extra disks":
				req.ExtraVolumes = []resource.LaunchVolume{{}}
			case "root size":
				req.RootVolumeSize = 16
			case "read only":
				w.b.cfg.ReadOnly = true
			}
			before := len(w.f.RequestMethods())
			_, err := w.b.RunInstances(t.Context(), m, req)
			if err == nil {
				t.Fatal("invalid input accepted")
			}
			if field == "userdata" && !resource.IsUnsupported(resource.AsError(err)) {
				t.Fatalf("user data=%v", err)
			}
			for _, method := range w.f.RequestMethods()[before:] {
				if method != http.MethodGet {
					t.Fatalf("invalid input wrote %s", method)
				}
			}
		})
	}
}

func TestRunInstancesSkipsUnreadableTemplate(t *testing.T) {
	const otherUUID = "7d444840-9dc0-41e1-a5cc-a5b8a1c4f2b1"
	second := func(s *pvefake.Scenario) {
		vm := s.VMs[0]
		vm.VMID, vm.Config = 150, maps.Clone(vm.Config)
		vm.Config["smbios1"] = "uuid=" + otherUUID
		vm.Config["scsi0"] = "local:vm-150-disk-0,serial=0123456789abcdef1"
		vm.Snapshots = nil
		s.VMs = append(s.VMs, vm)
		s.Storages[0].Content = append(s.Storages[0].Content, pvefake.StorageContent{
			VolID: "local:vm-150-disk-0", Content: "images", Size: 8 << 30, VMID: 150,
		})
	}
	w, m, req := launchBackend(t, false, second)
	w.failConfig = "/qemu/100/config"
	other, _ := newIDs(t, "test").Image(otherUUID)
	unreadable := req.ImageID
	req.ImageID, req.Count = other, 1
	got, err := w.b.RunInstances(t.Context(), m, req)
	if err != nil || len(got.Items) != 1 || len(w.forms) != 1 {
		t.Fatalf("readable template behind an unreadable one: %v; clones=%d", err, len(w.forms))
	}
	if marker, _, err := ReadLaunchMarker(w.forms[0].Get("description")); err != nil || marker.Image != other {
		t.Fatalf("clone marker=%+v %v", marker, err)
	}
	m.Key, req.ImageID = strings.Repeat("b", 64), unreadable
	_, err = w.b.RunInstances(t.Context(), m, req)
	if err == nil || resource.CodeOf(err) == resource.CodeNotFound || len(w.forms) != 1 {
		t.Fatalf("unreadable requested template = %v; clones=%d", err, len(w.forms))
	}
}
