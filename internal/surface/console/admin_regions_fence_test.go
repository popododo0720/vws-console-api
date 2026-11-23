package console

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// simDaemon applies the daemon's generation rule to what the console sends:
// the highest accepted generation is kept, a removal is a tombstone, and an
// older or equal message after a removal is refused.
type simDaemon struct {
	mu           sync.Mutex
	generation   int64
	deregistered bool
	registered   bool
}

func (d *simDaemon) register(data json.RawMessage) error {
	var req struct {
		Generation int64 `json:"generation"`
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if req.Generation < d.generation || req.Generation == d.generation && d.deregistered {
		return &resource.Error{Code: resource.CodeConflict, Message: "stale"}
	}
	d.generation, d.deregistered, d.registered = req.Generation, false, true
	return nil
}

func (d *simDaemon) deregister(generation int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if generation < d.generation || generation == d.generation && !d.deregistered {
		return &resource.Error{Code: resource.CodeConflict, Message: "stale"}
	}
	d.generation, d.deregistered, d.registered = generation, true, false
	return nil
}

func (d *simDaemon) active() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.registered
}

func fenceFixture(t *testing.T) (loginEnv, *store.Registry, *handler, *simDaemon) {
	t.Helper()
	e, g, _, _ := accountFixture(t)
	h := e.h.(*handler)
	d := &simDaemon{}
	h.regionRegistration = func(_ context.Context, _ string, data json.RawMessage) error { return d.register(data) }
	h.regionDeregistration = func(_ context.Context, _, _ string, generation int64) error {
		return d.deregister(generation)
	}
	return e, g, h, d
}

func awaitSignal(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(10 * time.Second):
		t.Fatal("interleaving point never reached")
	}
}

// A PATCH whose registration push is still in flight when a DELETE runs to
// the end must not bring the daemon back: the push carries an older generation
// than the removal.
func TestRegionDeleteFencesAPushInFlight(t *testing.T) {
	e, g, h, d := fenceFixture(t)
	post := regionCall(t, e, "POST", validRegion(), "", 201)
	pushing, release := make(chan struct{}), make(chan struct{})
	h.regionRegistration = func(_ context.Context, _ string, data json.RawMessage) error {
		close(pushing)
		<-release
		return d.register(data)
	}
	patched := make(chan int, 1)
	go func() {
		rec := e.do(t, "PATCH", regionPath+"/pve-test-1", `{"zones":[{"letter":"b"}]}`,
			map[string]string{"Authorization": "Bearer tok", "If-Match": post.Header().Get("ETag")})
		patched <- rec.Code
	}()
	awaitSignal(t, pushing)
	regionCall(t, e, "DELETE", nil, "", 204)
	close(release)
	if code := <-patched; code == http.StatusOK {
		t.Fatalf("the PATCH reported success after the region was deleted")
	}
	if d.active() {
		t.Fatal("a delayed push brought the daemon back after the delete")
	}
	if _, err := g.Regions().Get(t.Context(), "pve-test-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("record: %v", err)
	}
}

// While a DELETE waits for the daemon, a PATCH is refused before it pushes
// anything, and a project mapping is refused by the registry; the delete then
// finishes.
func TestRegionDeleteReservesTheRegion(t *testing.T) {
	e, g, h, d := fenceFixture(t)
	post := regionCall(t, e, "POST", validRegion(), "", 201)
	calling, release := make(chan struct{}), make(chan struct{})
	h.regionDeregistration = func(_ context.Context, _, _ string, generation int64) error {
		close(calling)
		<-release
		return d.deregister(generation)
	}
	pushes := 0
	h.regionRegistration = func(context.Context, string, json.RawMessage) error {
		pushes++
		return nil
	}
	deleted := make(chan int, 1)
	go func() {
		rec := e.do(t, "DELETE", regionPath+"/pve-test-1", "", map[string]string{"Authorization": "Bearer tok"})
		deleted <- rec.Code
	}()
	awaitSignal(t, calling)
	rec := e.do(t, "PATCH", regionPath+"/pve-test-1", `{}`,
		map[string]string{"Authorization": "Bearer tok", "If-Match": post.Header().Get("ETag")})
	if rec.Code != http.StatusConflict || pushes != 0 {
		t.Fatalf("PATCH of a reserved region: %d, pushes %d", rec.Code, pushes)
	}
	_, err := g.Projects().Put(t.Context(), store.Project{
		Project: "123456789012", Pools: []store.ProjectPool{{Region: "pve-test-1", Pool: "mapped"}},
	})
	if !errors.Is(err, store.ErrRegionDeleting) {
		t.Fatalf("a mapping committed during the daemon call: %v", err)
	}
	close(release)
	if code := <-deleted; code != http.StatusNoContent {
		t.Fatalf("DELETE = %d", code)
	}
	if _, err := g.Regions().Get(t.Context(), "pve-test-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("record: %v", err)
	}
}

// A mapping that is already there refuses the delete before the daemon is
// touched and leaves the region editable.
func TestRegionDeleteRefusedByAMappingReleasesTheReservation(t *testing.T) {
	e, g, h, d := fenceFixture(t)
	post := regionCall(t, e, "POST", validRegion(), "", 201)
	calls := 0
	h.regionDeregistration = func(context.Context, string, string, int64) error {
		calls++
		return nil
	}
	if _, err := g.Projects().Put(t.Context(), store.Project{
		Project: "123456789012", Pools: []store.ProjectPool{{Region: "pve-test-1", Pool: "mapped"}},
	}); err != nil {
		t.Fatal(err)
	}
	regionCall(t, e, "DELETE", nil, "", 409)
	stored, err := g.Regions().Get(t.Context(), "pve-test-1")
	if err != nil || stored.Deleting || calls != 0 || !d.active() {
		t.Fatalf("reservation after a refusal: %+v %v, daemon calls %d", stored, err, calls)
	}
	regionCall(t, e, "PATCH", map[string]any{}, `"`+itoa(stored.Version)+`"`, 200)
	_ = post
}

// A daemon that was never reached, or refused, committed nothing: the
// reservation is released and the region stays editable.
func TestRegionDeleteDefinitiveFailureReleasesTheReservation(t *testing.T) {
	e, g, h, d := fenceFixture(t)
	regionCall(t, e, "POST", validRegion(), "", 201)
	for _, failure := range []error{
		&net.OpError{Op: "dial", Err: errors.New("refused")},
		&resource.Error{Code: resource.CodeConflict, Message: "stale"},
		ErrRegionLegacy,
	} {
		h.regionDeregistration = func(context.Context, string, string, int64) error { return failure }
		regionCall(t, e, "DELETE", nil, "", 503)
		stored, err := g.Regions().Get(t.Context(), "pve-test-1")
		if err != nil || stored.Deleting {
			t.Fatalf("reservation after %v: %+v %v", failure, stored, err)
		}
		regionCall(t, e, "PATCH", map[string]any{}, `"`+itoa(stored.Version)+`"`, 200)
	}
	h.regionDeregistration = func(_ context.Context, _, _ string, generation int64) error {
		return d.deregister(generation)
	}
	regionCall(t, e, "DELETE", nil, "", 204)
	if d.active() {
		t.Fatal("daemon still registered")
	}
}

// A lost reply may hide a committed removal: the region stays reserved, nothing
// can edit or map it, and a repeat uses the same generation and finishes.
func TestRegionDeleteLostReplyKeepsTheReservation(t *testing.T) {
	e, g, h, d := fenceFixture(t)
	regionCall(t, e, "POST", validRegion(), "", 201)
	var generations []int64
	h.regionDeregistration = func(_ context.Context, _, _ string, generation int64) error {
		generations = append(generations, generation)
		if len(generations) == 1 {
			if err := d.deregister(generation); err != nil { // committed, reply lost
				return err
			}
			return context.DeadlineExceeded
		}
		return d.deregister(generation)
	}
	rec := regionCall(t, e, "DELETE", nil, "", 503)
	if !strings.Contains(rec.Body.String(), "repeat the delete") {
		t.Fatalf("message: %s", rec.Body)
	}
	stored, err := g.Regions().Get(t.Context(), "pve-test-1")
	if err != nil || !stored.Deleting || d.active() {
		t.Fatalf("after a lost reply: %+v %v active=%v", stored, err, d.active())
	}
	regionCall(t, e, "PATCH", map[string]any{}, `"`+itoa(stored.Version)+`"`, 409)
	if _, err := g.Projects().Put(t.Context(), store.Project{
		Project: "123456789012", Pools: []store.ProjectPool{{Region: "pve-test-1", Pool: "p"}},
	}); !errors.Is(err, store.ErrRegionDeleting) {
		t.Fatalf("mapping after a lost reply: %v", err)
	}
	regionCall(t, e, "DELETE", nil, "", 204)
	if len(generations) != 2 || generations[0] != generations[1] {
		t.Fatalf("the repeat used another generation: %v", generations)
	}
	if _, err := g.Regions().Get(t.Context(), "pve-test-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("record: %v", err)
	}
}

// A second DELETE joins the reservation of the first and never clears it, so no
// mapping can commit while the first call talks to the daemon.
func TestConcurrentRegionDeletesShareOneReservation(t *testing.T) {
	e, g, h, d := fenceFixture(t)
	regionCall(t, e, "POST", validRegion(), "", 201)
	first, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	calls := 0
	h.regionDeregistration = func(_ context.Context, _, _ string, generation int64) error {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			close(first)
			<-release
			return d.deregister(generation)
		}
		return &net.OpError{Op: "dial", Err: errors.New("refused")} // would release if it owned the mark
	}
	done := make(chan int, 1)
	go func() {
		done <- e.do(t, "DELETE", regionPath+"/pve-test-1", "", map[string]string{"Authorization": "Bearer tok"}).Code
	}()
	awaitSignal(t, first)
	regionCall(t, e, "DELETE", nil, "", 503)
	stored, err := g.Regions().Get(t.Context(), "pve-test-1")
	if err != nil || !stored.Deleting {
		t.Fatalf("a joining DELETE cleared the reservation: %+v %v", stored, err)
	}
	if _, err := g.Projects().Put(t.Context(), store.Project{
		Project: "123456789012", Pools: []store.ProjectPool{{Region: "pve-test-1", Pool: "p"}},
	}); !errors.Is(err, store.ErrRegionDeleting) {
		t.Fatalf("a mapping committed during the first call: %v", err)
	}
	close(release)
	if code := <-done; code != http.StatusNoContent {
		t.Fatalf("first DELETE = %d", code)
	}
}

func itoa(v store.Version) string {
	return strconv.FormatInt(int64(v), 10)
}
