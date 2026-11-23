package console

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

// fakeDaemon serves the region daemon's registration and deregistration
// routes over mutual TLS and applies the daemon's generation rule: the highest
// accepted generation is kept, a removal leaves a tombstone, and an older
// message, or a registration at the tombstone's generation, is refused.
type fakeDaemon struct {
	mu           sync.Mutex
	generation   int64
	deregistered bool
	registered   bool
	pushes       []json.RawMessage

	up, down *regionapi.Client
}

func (d *fakeDaemon) register(_ context.Context, data json.RawMessage) error {
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
	d.pushes = append(d.pushes, data)
	return nil
}

func (d *fakeDaemon) deregister(_ context.Context, data json.RawMessage) error {
	var req struct {
		Generation int64 `json:"generation"`
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if req.Generation < d.generation || req.Generation == d.generation && !d.deregistered {
		return &resource.Error{Code: resource.CodeConflict, Message: "stale"}
	}
	d.generation, d.deregistered, d.registered = req.Generation, true, false
	return nil
}

func (d *fakeDaemon) state() (generation int64, registered bool, pushes int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.generation, d.registered, len(d.pushes)
}

// deleteFixture wires the console to a fakeDaemon through the real region
// client. deregister decides, per call, how the daemon call behaves.
func deleteFixture(t *testing.T) (loginEnv, *store.Registry, *fakeDaemon, *handler) {
	t.Helper()
	e, g, _, _ := accountFixture(t)
	d := &fakeDaemon{}
	srv := httptest.NewTLSServer(regionapi.WithRegistration(d.register,
		regionapi.WithDeregistration(d.deregister, http.NotFoundHandler())))
	t.Cleanup(srv.Close)
	config := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	config.Certificates = srv.TLS.Certificates
	closed, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := "https://" + closed.Addr().String()
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if d.up, err = regionapi.NewClient(srv.URL, config); err != nil {
		t.Fatal(err)
	}
	if d.down, err = regionapi.NewClient(unreachable, config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.up.Close)
	t.Cleanup(d.down.Close)
	h := e.h.(*handler)
	h.regionRegistration = func(ctx context.Context, _ string, data json.RawMessage) error {
		return d.up.Register(ctx, data)
	}
	h.regionDeregistration = func(ctx context.Context, _, region string, generation int64) error {
		return d.up.Deregister(ctx, region, generation)
	}
	return e, g, d, h
}

func mapRegion(t *testing.T, g *store.Registry) error {
	t.Helper()
	_, err := g.Projects().Put(t.Context(), store.Project{
		Project: "123456789012", Pools: []store.ProjectPool{{Region: "pve-test-1", Pool: "p"}},
	})
	return err
}

// assertMarked checks that the region is still marked for deletion and that
// neither a PATCH nor a project mapping can commit.
func assertMarked(t *testing.T, e loginEnv, g *store.Registry, d *fakeDaemon) {
	t.Helper()
	stored, err := g.Regions().Get(t.Context(), "pve-test-1")
	if err != nil || !stored.Deleting {
		t.Fatalf("mark: %+v %v", stored, err)
	}
	_, _, pushes := d.state()
	rec := regionCall(t, e, "PATCH", map[string]any{}, strconv.Quote(strconv.FormatInt(int64(stored.Version), 10)), 409)
	if _, _, after := d.state(); !strings.Contains(rec.Body.String(), "being deleted") || after != pushes {
		t.Fatalf("PATCH of a marked region: %s, pushes %d -> %d", rec.Body, pushes, after)
	}
	if err := mapRegion(t, g); !errors.Is(err, store.ErrRegionDeleting) {
		t.Fatalf("a mapping committed on a marked region: %v", err)
	}
}

func assertDeleted(t *testing.T, g *store.Registry, d *fakeDaemon) {
	t.Helper()
	if _, err := g.Regions().Get(t.Context(), "pve-test-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("record: %v", err)
	}
	if err := g.ClaimCluster(t.Context(), "test", "pve-other-1", time.Now()); err != nil {
		t.Fatalf("cluster claim kept: %v", err)
	}
	if _, registered, _ := d.state(); registered {
		t.Fatal("the daemon still holds the registration")
	}
}

func TestRegionDeleteDeregistersTheDaemon(t *testing.T) {
	e, g, d, _ := deleteFixture(t)
	regionCall(t, e, "POST", validRegion(), "", 201)
	pushed, registered, _ := d.state()
	if !registered || pushed <= 0 {
		t.Fatalf("registration: generation %d registered %v", pushed, registered)
	}
	regionCall(t, e, "DELETE", nil, "", 204)
	if removed, _, _ := d.state(); removed <= pushed {
		t.Fatalf("removal generation %d is not above the pushed %d", removed, pushed)
	}
	assertDeleted(t, g, d)
}

func TestRegionDeleteWithTheDaemonUnreachable(t *testing.T) {
	e, g, d, h := deleteFixture(t)
	regionCall(t, e, "POST", validRegion(), "", 201)
	var generations []int64
	reachable := false
	h.regionDeregistration = func(ctx context.Context, _, region string, generation int64) error {
		generations = append(generations, generation)
		if !reachable {
			return d.down.Deregister(ctx, region, generation)
		}
		return d.up.Deregister(ctx, region, generation)
	}
	rec := regionCall(t, e, "DELETE", nil, "", 503)
	if !strings.Contains(rec.Body.String(), "repeat the delete") || !strings.Contains(rec.Body.String(), "dial") {
		t.Fatalf("message: %s", rec.Body)
	}
	assertMarked(t, e, g, d)
	if _, registered, _ := d.state(); !registered {
		t.Fatal("an unreachable daemon lost its registration")
	}
	reachable = true
	regionCall(t, e, "DELETE", nil, "", 204)
	if len(generations) != 2 || generations[0] != generations[1] {
		t.Fatalf("the retry used another generation: %v", generations)
	}
	assertDeleted(t, g, d)
}

// AC 2 of #1071: once a call may have reached the daemon, a later definitive
// failure of another call must not release the mark. Two DELETEs overlap: the
// owner (which set the mark) waits inside its daemon call while a joiner runs.
// One of them commits on the daemon and loses its reply; the other cannot dial.
func TestRegionDeleteOverlappingCallsKeepTheMark(t *testing.T) {
	for _, tc := range []struct {
		name          string
		ownerCommits  bool
		joinerCommits bool
	}{
		{name: "joiner commits, owner cannot dial", joinerCommits: true},
		{name: "owner commits, joiner cannot dial", ownerCommits: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, g, d, h := deleteFixture(t)
			regionCall(t, e, "POST", validRegion(), "", 201)
			inOwner, resume := make(chan struct{}), make(chan struct{})
			var mu sync.Mutex
			calls := 0
			call := func(ctx context.Context, region string, generation int64, commits bool) error {
				if !commits {
					return d.down.Deregister(ctx, region, generation)
				}
				if err := d.up.Deregister(ctx, region, generation); err != nil {
					return err
				}
				return context.DeadlineExceeded // committed, reply lost
			}
			h.regionDeregistration = func(ctx context.Context, _, region string, generation int64) error {
				mu.Lock()
				calls++
				n := calls
				mu.Unlock()
				switch n {
				case 1:
					close(inOwner)
					<-resume
					return call(ctx, region, generation, tc.ownerCommits)
				case 2:
					return call(ctx, region, generation, tc.joinerCommits)
				}
				return d.up.Deregister(ctx, region, generation)
			}
			owner := make(chan int, 1)
			go func() {
				owner <- e.do(t, "DELETE", regionPath+"/pve-test-1", "",
					map[string]string{"Authorization": "Bearer tok"}).Code
			}()
			awaitSignal(t, inOwner)
			regionCall(t, e, "DELETE", nil, "", 503)
			close(resume)
			if code := <-owner; code != http.StatusServiceUnavailable {
				t.Fatalf("owner DELETE = %d", code)
			}
			if _, registered, _ := d.state(); registered {
				t.Fatal("the committed removal was undone")
			}
			assertMarked(t, e, g, d)
			regionCall(t, e, "DELETE", nil, "", 204)
			assertDeleted(t, g, d)
		})
	}
}

// A mapped region is refused in the same registry transaction that would mark
// it, so it is never marked and stays editable.
func TestRegionDeleteOfAMappedRegionIsNotMarked(t *testing.T) {
	e, g, d, h := deleteFixture(t)
	regionCall(t, e, "POST", validRegion(), "", 201)
	if err := mapRegion(t, g); err != nil {
		t.Fatal(err)
	}
	before, err := g.Regions().Get(t.Context(), "pve-test-1")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	h.regionDeregistration = func(context.Context, string, string, int64) error {
		calls++
		return nil
	}
	rec := regionCall(t, e, "DELETE", nil, "", 409)
	if !strings.Contains(rec.Body.String(), "project pool mappings") {
		t.Fatalf("message: %s", rec.Body)
	}
	stored, err := g.Regions().Get(t.Context(), "pve-test-1")
	if err != nil || stored.Deleting || stored.Version != before.Version || calls != 0 {
		t.Fatalf("after a refusal: %+v %v, daemon calls %d", stored, err, calls)
	}
	if _, registered, _ := d.state(); !registered {
		t.Fatal("a mapped region was deregistered")
	}
	regionCall(t, e, "PATCH", map[string]any{}, strconv.Quote(strconv.FormatInt(int64(stored.Version), 10)), 200)
}

// The last mapping is removed between attempts. The next DELETE marks the
// region and waits in its daemon call while a joined DELETE commits the removal
// and loses its reply; the first then fails to dial. Nothing clears the mark,
// a new mapping is refused, and a repeat completes.
func TestRegionDeleteAfterTheLastMappingIsRemoved(t *testing.T) {
	e, g, d, h := deleteFixture(t)
	regionCall(t, e, "POST", validRegion(), "", 201)
	mapping, err := g.Projects().Put(t.Context(), store.Project{ // another project than mapRegion's
		Project: "210987654321", Pools: []store.ProjectPool{{Region: "pve-test-1", Pool: "p"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	regionCall(t, e, "DELETE", nil, "", 409)
	mapping.Pools = nil
	if _, err := g.Projects().Put(t.Context(), mapping); err != nil {
		t.Fatal(err)
	}
	inFirst, resume := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	calls := 0
	h.regionDeregistration = func(ctx context.Context, _, region string, generation int64) error {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		switch n {
		case 1:
			close(inFirst)
			<-resume
			return d.down.Deregister(ctx, region, generation)
		case 2:
			if err := d.up.Deregister(ctx, region, generation); err != nil {
				return err
			}
			return context.DeadlineExceeded // committed, reply lost
		}
		return d.up.Deregister(ctx, region, generation)
	}
	first := make(chan int, 1)
	go func() {
		first <- e.do(t, "DELETE", regionPath+"/pve-test-1", "",
			map[string]string{"Authorization": "Bearer tok"}).Code
	}()
	awaitSignal(t, inFirst)
	regionCall(t, e, "DELETE", nil, "", 503)
	close(resume)
	if code := <-first; code != http.StatusServiceUnavailable {
		t.Fatalf("first DELETE = %d", code)
	}
	if _, registered, _ := d.state(); registered {
		t.Fatal("the committed removal was undone")
	}
	assertMarked(t, e, g, d)
	regionCall(t, e, "DELETE", nil, "", 204)
	assertDeleted(t, g, d)
}

// A region registered again under the same name gets a new record, whose
// version is above the removal generation, so the daemon accepts it after the
// tombstone and still refuses the old registration.
func TestRegionReRegisterAfterDelete(t *testing.T) {
	e, _, d, _ := deleteFixture(t)
	regionCall(t, e, "POST", validRegion(), "", 201)
	d.mu.Lock()
	old := d.pushes[0]
	d.mu.Unlock()
	regionCall(t, e, "DELETE", nil, "", 204)
	removed, _, _ := d.state()
	regionCall(t, e, "POST", validRegion(), "", 201)
	generation, registered, _ := d.state()
	if !registered || generation <= removed {
		t.Fatalf("re-registration: generation %d after removal %d, registered %v", generation, removed, registered)
	}
	if err := d.up.Register(t.Context(), old); resource.AsError(err).Code != resource.CodeConflict {
		t.Fatalf("the old registration was accepted again: %v", err)
	}
}

func awaitSignal(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(10 * time.Second):
		t.Fatal("interleaving point never reached")
	}
}
