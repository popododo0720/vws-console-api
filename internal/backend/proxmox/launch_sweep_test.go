package proxmox

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestLaunchSweepRestartAndBoundaries(t *testing.T) {
	for _, state := range []string{
		"stopped", "running", "partial tags", "finalized", "failed", "exactly ten minutes", "locked",
	} {
		t.Run(state, func(t *testing.T) {
			w, m, req := finalizeBackend(t)
			req.Count = 1
			if state == "locked" {
				checkLaunch(t, w.f.SetTaskDelay(time.Hour))
			}
			accepted, err := w.b.RunInstances(t.Context(), m, req)
			checkLaunch(t, err)
			vm := launchVM(t, w, 0)
			cfg, err := w.b.client.VMConfig(t.Context(), vm)
			checkLaunch(t, err)
			marker, _, err := ReadLaunchMarker(cfg.Description)
			checkLaunch(t, err)
			if marker.CreatedAt != 1700000000 {
				t.Fatalf("clone did not persist its creation time: %+v", marker)
			}
			switch state {
			case "running":
				_, err = w.b.client.Power(t.Context(), vm, "start", 0)
				checkLaunch(t, err)
			case "partial tags":
				checkLaunch(t, w.b.client.WriteConfig(t.Context(), vm, cfg.Digest,
					url.Values{"tags": {"vws.k." + m.Key[:24]}}))
			case "finalized":
				checkLaunch(t, w.b.FinalizeLaunches(t.Context(), admitFinalize))
			case "failed":
				checkLaunch(t, w.b.client.WriteConfig(t.Context(), vm, cfg.Digest,
					url.Values{"tags": {LaunchFailureTag}}))
			}
			age := 10*time.Minute + time.Second
			switch state {
			case "exactly ten minutes":
				age = 10 * time.Minute
			case "failed", "finalized":
				age = backend.ClientTokenWindow + backend.ClientTokenGrace + time.Hour
			}
			w.b.cfg.Now = func() time.Time { return time.Unix(1700000000, 0).Add(age) }
			w.b, err = New(t.Context(), w.b.client, Identity(w.b), w.b.cfg)
			checkLaunch(t, err)
			before := len(w.f.RequestMethods())
			checkLaunch(t, w.b.FinalizeLaunches(t.Context(), admitFinalize))
			deleted := state == "stopped" || state == "running" || state == "partial tags"
			rows, err := w.b.client.ClusterResources(t.Context(), pveclient.ResourceVM)
			checkLaunch(t, err)
			exists := slices.ContainsFunc(rows, func(row pveclient.ClusterResource) bool { return row.VMID == vm.VMID })
			if exists == deleted {
				t.Fatalf("deleted=%v inventory=%+v", deleted, rows)
			}
			if state == "failed" || state == "finalized" || state == "locked" {
				assertSweepReadOnly(t, w, before)
			}
			switch {
			case deleted:
				disks, err := w.b.client.StorageContent(t.Context(), vm.Node, "local")
				checkLaunch(t, err)
				if slices.ContainsFunc(disks, func(disk pveclient.StorageContent) bool { return disk.VMID == vm.VMID }) {
					t.Fatal("sweep left VM disks")
				}
			case state == "exactly ten minutes" || state == "finalized":
				assertFinalized(t, w, m, accepted)
			case state == "failed":
				recovered, err := w.b.RecoverLaunch(t.Context(), m.Scope, m.Key, m.Fingerprint)
				if err != nil || recovered.Operation.State != resource.OperationFailed || recovered.Operation.Error == nil {
					t.Fatalf("failed carrier lost after restart: %+v %v", recovered, err)
				}
			}
			before = len(w.f.RequestMethods())
			checkLaunch(t, w.b.FinalizeLaunches(t.Context(), admitFinalize))
			assertSweepReadOnly(t, w, before)
		})
	}
}

func assertSweepReadOnly(t *testing.T, w *launchWorld, before int) {
	t.Helper()
	if methods := w.f.RequestMethods()[before:]; slices.ContainsFunc(methods, func(method string) bool {
		return method != http.MethodGet
	}) {
		t.Fatalf("unexpected sweep writes: %v", methods)
	}
}

func TestLaunchSweepFreshRead(t *testing.T) {
	for _, race := range []string{"finalized", "failed", "pool moved", "pool moved after stop"} {
		t.Run(race, func(t *testing.T) {
			w, m, req := finalizeBackend(t)
			req.Count = 1
			_, err := w.b.RunInstances(t.Context(), m, req)
			checkLaunch(t, err)
			vm := launchVM(t, w, 0)
			cfg, err := w.b.client.VMConfig(t.Context(), vm)
			checkLaunch(t, err)
			marker, _, err := ReadLaunchMarker(cfg.Description)
			checkLaunch(t, err)
			reservation, err := newIDs(t, "test").Reservation(m.Key)
			checkLaunch(t, err)
			tags, err := LaunchMarkerTags(marker, reservation)
			checkLaunch(t, err)
			w.b.cfg.Now = func() time.Time { return time.Unix(1700000601, 0) }
			if race == "pool moved after stop" {
				_, err := w.b.client.Power(t.Context(), vm, "start", 0)
				checkLaunch(t, err)
			}
			configReads, inventories := 0, 0
			w.intercept = func(_ http.ResponseWriter, r *http.Request) bool {
				if r.Method != http.MethodGet {
					return false
				}
				if strings.HasSuffix(r.URL.Path, "/"+strconv.Itoa(vm.VMID)+"/config") {
					configReads++
					if configReads == 2 && (race == "finalized" || race == "failed") {
						value := strings.Join(tags, ";")
						if race == "failed" {
							value = LaunchFailureTag
						}
						checkLaunch(t, w.b.client.WriteConfig(r.Context(), vm, cfg.Digest, url.Values{"tags": {value}}))
					}
				}
				if strings.HasSuffix(r.URL.Path, "/cluster/resources") && r.URL.Query().Get("type") == "vm" {
					inventories++
					if race == "pool moved" && inventories == 2 || race == "pool moved after stop" && inventories == 3 {
						checkLaunch(t, w.f.MoveVM(vm.VMID, "images"))
					}
				}
				return false
			}
			before := len(w.f.Requests())
			err = w.b.FinalizeLaunches(t.Context(), admitFinalize)
			if strings.HasPrefix(race, "pool moved") {
				if resource.CodeOf(err) != resource.CodePermissionDenied {
					t.Fatalf("moved pool was not refused: %v", err)
				}
			} else {
				checkLaunch(t, err)
			}
			for _, request := range w.f.Requests()[before:] {
				if strings.HasPrefix(request, "DELETE ") {
					t.Fatalf("sweep deleted a changed VM: %s", request)
				}
			}
			_, err = w.b.client.VMConfig(t.Context(), vm)
			checkLaunch(t, err)
		})
	}
}

func TestLaunchSweepRetryAndFence(t *testing.T) {
	for _, cut := range []string{"fence", "destroy", "stop"} {
		t.Run(cut, func(t *testing.T) {
			w, m, req := finalizeBackend(t)
			req.Count = 1
			_, err := w.b.RunInstances(t.Context(), m, req)
			checkLaunch(t, err)
			vm := launchVM(t, w, 0)
			if cut == "stop" {
				_, err := w.b.client.Power(t.Context(), vm, "start", 0)
				checkLaunch(t, err)
			}
			w.b.cfg.Now = func() time.Time { return time.Unix(1700000601, 0) }
			fence := admitFinalize
			if cut == "fence" {
				fence = func(context.Context) error { return errors.New("leadership lost") }
			} else {
				w.f.FailNext("qm"+cut, "injected task failure")
			}
			before := len(w.f.RequestMethods())
			if err := w.b.FinalizeLaunches(t.Context(), fence); err == nil {
				t.Fatal("sweep ignored failure")
			}
			if cut == "fence" {
				assertSweepReadOnly(t, w, before)
			}
			_, err = w.b.client.VMConfig(t.Context(), vm)
			checkLaunch(t, err)
			w.b, err = New(t.Context(), w.b.client, Identity(w.b), w.b.cfg)
			checkLaunch(t, err)
			checkLaunch(t, w.b.FinalizeLaunches(t.Context(), admitFinalize))
			rows, err := w.b.client.ClusterResources(t.Context(), pveclient.ResourceVM)
			checkLaunch(t, err)
			if slices.ContainsFunc(rows, func(row pveclient.ClusterResource) bool { return row.VMID == vm.VMID }) {
				t.Fatal("restart did not resume the sweep")
			}
		})
	}
}

func TestLaunchSweepCreationTime(t *testing.T) {
	b := &Backend{cfg: RegionConfig{Now: func() time.Time { return time.Unix(1700000600, 0) }}}
	for _, tc := range []struct {
		created int64
		expired bool
	}{
		{0, false},
		{-1, false},
		{1700000000, false},
		{1700000001, false},
		{1699999999, true},
		{1<<63 - 1, false},
	} {
		if got := b.launchExpired(LaunchMarker{CreatedAt: tc.created}); got != tc.expired {
			t.Errorf("created=%d expired=%v want=%v", tc.created, got, tc.expired)
		}
	}
}

func TestLaunchSweepMarkerTimestamp(t *testing.T) {
	w, m, req := finalizeBackend(t)
	req.Count = 1
	accepted, err := w.b.RunInstances(t.Context(), m, req)
	checkLaunch(t, err)
	vm := launchVM(t, w, 0)
	cfg, err := w.b.client.VMConfig(t.Context(), vm)
	checkLaunch(t, err)
	marker, _, err := ReadLaunchMarker(cfg.Description)
	checkLaunch(t, err)
	marker.CreatedAt = 0
	legacy, err := WithLaunchMarker(cfg.Description, marker)
	checkLaunch(t, err)
	for _, value := range []string{"0", "-1", "bad", "+1700000000", "9223372036854775808"} {
		if _, _, err := ReadLaunchMarker(legacy + " created=" + value); err == nil {
			t.Errorf("accepted malformed created=%s", value)
		}
	}
	checkLaunch(t, w.b.client.WriteConfig(t.Context(), vm, cfg.Digest, url.Values{"description": {legacy}}))
	w.b.cfg.Now = func() time.Time { return time.Unix(1700000000, 0).Add(48 * time.Hour) }
	w.b, err = New(t.Context(), w.b.client, Identity(w.b), w.b.cfg)
	checkLaunch(t, err)
	checkLaunch(t, w.b.FinalizeLaunches(t.Context(), admitFinalize))
	assertFinalized(t, w, m, accepted)
}
