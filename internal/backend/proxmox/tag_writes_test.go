package proxmox

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func tagMutationIDs() (resource.InstanceID, resource.VolumeID) {
	ids, _ := NewIDs("test")
	iid, _, _ := ids.Instance(VM{UUID: "5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10"})
	vid, _, _ := ids.Volume("0123456789abcdef0", "", "")
	return iid, vid
}

func tagWriteBackend(
	t *testing.T, holder bool, intercept func(*pvefake.Fake, http.ResponseWriter, *http.Request) bool,
) (*Backend, *pvefake.Fake) {
	t.Helper()
	s := mutationScenario()
	s.VMs[0].Config["scsi1"] = "local:vm-100-disk-1,serial=1123456789abcdef0"
	disk := s.Storages[0].Content[0]
	disk.VolID = "local:vm-100-disk-1"
	s.Storages[0].Content = append(s.Storages[0].Content, disk)
	s.Tokens[0].Secret = "test-secret"
	s.Roles = append(s.Roles,
		pvefake.Role{ID: "TagWriter", Privs: []string{"VM.Audit", "VM.Config.Options", "Pool.Audit"}})
	s.Tokens[0].ACL = append(s.Tokens[0].ACL, pvefake.ACE{Path: "/pool/123456789012", Role: "TagWriter"})
	s.VMs[0].Tags = "operator;vws.k.keep;vws.vt.ffffffff.other.keep"
	if holder {
		s.VMs[0].Tags += ";vws.holder"
	}
	s.VMs[0].Config["description"] = "operator notes"
	f, err := pvefake.New(s)
	if err != nil {
		t.Fatal(err)
	}
	c := startupClient(t, func(w http.ResponseWriter, r *http.Request) {
		if intercept != nil && intercept(f, w, r) {
			return
		}
		f.ServeHTTP(w, r)
	})
	t.Cleanup(func() {
		if violations := f.PoolWriteViolations(); len(violations) != 0 {
			t.Fatalf("pool writes: %v", violations)
		}
	})
	b, err := New(t.Context(), c, registration(), RegionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return b, f
}

func TestTagWritesRoundTripRetryRestart(t *testing.T) {
	for _, holder := range []bool{false, true} {
		t.Run(fmt.Sprint(holder), func(t *testing.T) {
			b, _ := tagWriteBackend(t, holder, nil)
			iid, vid := tagMutationIDs()
			m := backend.Mutation{Scope: inventoryScope(), Key: "tag-token"}
			want := map[string]string{"Name": "web", "unicode": "\u00e9\u96ea", "empty": ""}
			if !holder {
				want[strings.Repeat("x", 128)] = "overflow"
				var op resource.OperationID
				for range 2 {
					got, err := b.CreateTags(t.Context(), m,
						resource.CreateTagsRequest{IDs: []resource.InstanceID{iid}, Tags: want})
					if err != nil || len(got.Items) != 1 || !maps.Equal(got.Items[0].Tags, want) {
						t.Fatalf("instance round trip: %+v %v", got, err)
					}
					if !op.IsZero() && op != got.Operation.ID {
						t.Fatal("retry changed operation ID")
					}
					op = got.Operation.ID
					b, err = New(t.Context(), b.client, registration(), b.cfg)
					if err != nil {
						t.Fatal(err)
					}
				}
				gotOp, err := b.GetOperation(t.Context(), m.Scope, op)
				if err != nil || gotOp.State != resource.OperationSucceeded {
					t.Fatalf("restarted operation: %+v %v", gotOp, err)
				}
				// Move an overflow key back inline without leaving a stale copy.
				if _, err := b.CreateTags(t.Context(), m, resource.CreateTagsRequest{
					IDs: []resource.InstanceID{iid}, Tags: map[string]string{"Name": strings.Repeat("z", 128)},
				}); err != nil {
					t.Fatal(err)
				}
				if _, err := b.CreateTags(t.Context(), m, resource.CreateTagsRequest{
					IDs: []resource.InstanceID{iid}, Tags: map[string]string{"Name": "web"},
				}); err != nil {
					t.Fatal(err)
				}
				if _, err := b.DeleteTags(t.Context(), m,
					resource.DeleteTagsRequest{IDs: []resource.InstanceID{iid}}); err != nil {
					t.Fatal(err)
				}
			}
			delete(want, strings.Repeat("x", 128))
			other, _ := resource.Parse[resource.VolumeID]("vol-1123456789abcdef0")
			var op resource.OperationID
			for range 2 {
				got, err := b.TagVolumes(t.Context(), m,
					resource.TagVolumesRequest{IDs: []resource.VolumeID{vid, other}, Tags: want})
				if err != nil || len(got.Items) != 2 || !maps.Equal(got.Items[0].Tags, want) ||
					!maps.Equal(got.Items[1].Tags, want) {
					t.Fatalf("volume round trip: %+v %v", got, err)
				}
				readOp, readErr := b.GetOperation(t.Context(), m.Scope, got.Operation.ID)
				if readErr != nil || len(readOp.Targets) != 1 || len(got.Operation.Targets) != 1 ||
					readOp.Targets[0] != got.Operation.Targets[0] {
					t.Fatalf("operation targets changed: %+v %+v %v", got.Operation, readOp, readErr)
				}
				if !op.IsZero() && op != got.Operation.ID {
					t.Fatal("retry changed volume operation ID")
				}
				op = got.Operation.ID
				b, err = New(t.Context(), b.client, registration(), b.cfg)
				if err != nil {
					t.Fatal(err)
				}
			}
			empty, wrong := "", "wrong"
			got, err := b.UntagVolumes(t.Context(), m, resource.UntagVolumesRequest{
				IDs:  []resource.VolumeID{vid, other},
				Tags: []resource.TagSelector{{Key: "Name", Value: &wrong}, {Key: "empty", Value: &empty}, {Key: "unicode"}},
			})
			if err != nil || len(got.Items) != 2 || !maps.Equal(got.Items[0].Tags, map[string]string{"Name": "web"}) {
				t.Fatalf("selectors: %+v %v", got, err)
			}
			for range 2 {
				if _, err := b.UntagVolumes(t.Context(), m,
					resource.UntagVolumesRequest{IDs: []resource.VolumeID{vid, other}}); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := b.client.VMConfig(t.Context(), pveclient.VM{Node: "pve1", VMID: 100})
			if err != nil {
				t.Fatal(err)
			}
			for _, tag := range []string{"operator", "vws.k.keep", "vws.vt.ffffffff.other.keep"} {
				if !slices.Contains(strings.Split(cfg.Tags, ";"), tag) {
					t.Fatalf("lost operator or system tag %s: %+v", tag, cfg)
				}
			}
			if cfg.Description != "operator notes" {
				t.Fatalf("lost description: %q", cfg.Description)
			}
		})
	}
}

func TestTagWritesRejectReservedAndBoundary(t *testing.T) {
	b, f := tagWriteBackend(t, false, nil)
	iid, vid := tagMutationIDs()
	m := backend.Mutation{Scope: inventoryScope(), Key: "boundary"}
	for _, key := range []string{
		"aws:key", "AWS:key", "vws:key", "VWS.KEY", "", "\xff", "bad\nkey", strings.Repeat("x", 129),
	} {
		_, createErr := b.CreateTags(t.Context(), m, resource.CreateTagsRequest{
			IDs: []resource.InstanceID{iid}, Tags: map[string]string{key: "value"},
		})
		_, deleteErr := b.DeleteTags(t.Context(), m, resource.DeleteTagsRequest{
			IDs: []resource.InstanceID{iid}, Tags: []resource.TagSelector{{Key: key}},
		})
		_, tagErr := b.TagVolumes(t.Context(), m, resource.TagVolumesRequest{
			IDs: []resource.VolumeID{vid}, Tags: map[string]string{key: "value"},
		})
		_, untagErr := b.UntagVolumes(t.Context(), m, resource.UntagVolumesRequest{
			IDs: []resource.VolumeID{vid}, Tags: []resource.TagSelector{{Key: key}},
		})
		for _, err := range []error{createErr, deleteErr, tagErr, untagErr} {
			if resource.CodeOf(err) != resource.CodeInvalidArgument {
				t.Fatalf("key %q: %v", key, err)
			}
		}
	}
	_, err := b.TagVolumes(t.Context(), m, resource.TagVolumesRequest{
		IDs: []resource.VolumeID{vid}, Tags: map[string]string{strings.Repeat("x", 128): "long"},
	})
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("long volume tag: %v", err)
	}
	overflow := map[string]string{}
	for i := range 40 {
		overflow[fmt.Sprintf("key%d", i)] = strings.Repeat("x", 256)
	}
	if _, err := b.CreateTags(t.Context(), m, resource.CreateTagsRequest{
		IDs: []resource.InstanceID{iid}, Tags: overflow,
	}); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("description budget: %v", err)
	}
	missing, _ := resource.Parse[resource.InstanceID]("i-fffffffffffffffff")
	_, err = b.CreateTags(t.Context(), m, resource.CreateTagsRequest{
		IDs: []resource.InstanceID{iid, missing}, Tags: map[string]string{"env": "dev"},
	})
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("missing later ID: %v", err)
	}
	for _, r := range f.Requests() {
		if !strings.HasPrefix(r, "GET ") {
			t.Fatalf("invalid request wrote PVE: %s", r)
		}
	}
}

func TestTagWritesPreserveOwnerReadFailure(t *testing.T) {
	reads := 0
	b, _ := tagWriteBackend(t, true, func(_ *pvefake.Fake, w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/config") {
			reads++
		}
		if reads > 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	_, vid := tagMutationIDs()
	_, err := b.TagVolumes(t.Context(), backend.Mutation{Scope: inventoryScope()},
		resource.TagVolumesRequest{IDs: []resource.VolumeID{vid}, Tags: map[string]string{"env": "dev"}})
	he, _ := errors.AsType[*pveclient.HTTPError](err)
	if he == nil || he.Status != http.StatusServiceUnavailable {
		t.Fatalf("owner read failure became missing volume: %v", err)
	}
}

func TestTagWritesPropagateWriteFailures(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusInternalServerError, http.StatusOK} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			writes := 0
			b, _ := tagWriteBackend(t, false, func(_ *pvefake.Fake, w http.ResponseWriter, r *http.Request) bool {
				if r.Method != http.MethodPut {
					return false
				}
				writes++
				w.WriteHeader(status)
				fmt.Fprint(w, "invalid JSON")
				return true
			})
			iid, _ := tagMutationIDs()
			_, err := b.CreateTags(t.Context(), backend.Mutation{Scope: inventoryScope()},
				resource.CreateTagsRequest{IDs: []resource.InstanceID{iid}, Tags: map[string]string{"env": "dev"}})
			if err == nil || writes != 1 {
				t.Fatalf("write failure swallowed or blindly retried: writes=%d err=%v", writes, err)
			}
			page, err := b.DescribeInstances(t.Context(), inventoryScope(), resource.InstanceQuery{})
			if err != nil || len(page.Items) != 1 || len(page.Items[0].Tags) != 0 {
				t.Fatalf("failed write changed tags: %+v %v", page, err)
			}
		})
	}
}

func TestTagWritesDigestConflict(t *testing.T) {
	for _, conflicts := range []int{0, 1, 2} {
		for _, volume := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/volume=%v", conflicts, volume), func(t *testing.T) {
				writes := 0
				b, _ := tagWriteBackend(t, false, func(f *pvefake.Fake, w http.ResponseWriter, r *http.Request) bool {
					if r.Method != http.MethodPut {
						return false
					}
					writes++
					if err := r.ParseForm(); err != nil || r.Form.Get("digest") == "" {
						t.Errorf("missing digest: %v", err)
					}
					if writes <= conflicts {
						// Simulate an operator edit after our read, through the real fake.
						edit := httptest.NewRequestWithContext(t.Context(), http.MethodPut,
							"/api2/json/nodes/pve1/qemu/100/config",
							strings.NewReader(url.Values{"description": {fmt.Sprintf("concurrent %d", writes)}}.Encode()))
						edit.Header = r.Header.Clone()
						result := httptest.NewRecorder()
						f.ServeHTTP(result, edit)
						if result.Code != http.StatusOK {
							t.Errorf("operator edit: %d %s", result.Code, result.Body.String())
						}
					}
					return false
				})
				iid, vid := tagMutationIDs()
				m := backend.Mutation{Scope: inventoryScope(), Key: "cas"}
				var err error
				if volume {
					_, err = b.TagVolumes(t.Context(), m, resource.TagVolumesRequest{
						IDs: []resource.VolumeID{vid}, Tags: map[string]string{"env": "dev"},
					})
				} else {
					_, err = b.CreateTags(t.Context(), m, resource.CreateTagsRequest{
						IDs: []resource.InstanceID{iid}, Tags: map[string]string{"env": "dev"},
					})
				}
				if conflicts == 2 {
					e, _ := errors.AsType[*resource.Error](err)
					if e == nil || e.Code != resource.CodeConflict || e.Kind != resource.KindOperation || writes != 2 {
						t.Fatalf("conflict must stop after one retry: writes=%d err=%v", writes, err)
					}
				} else if err != nil || writes != conflicts+1 {
					t.Fatalf("writes=%d err=%v", writes, err)
				}
				cfg, readErr := b.client.VMConfig(t.Context(), pveclient.VM{Node: "pve1", VMID: 100})
				if readErr != nil || (conflicts > 0 && cfg.Description != fmt.Sprintf("concurrent %d", conflicts)) {
					t.Fatalf("lost concurrent edit: %+v %v", cfg, readErr)
				}
			})
		}
	}
}
