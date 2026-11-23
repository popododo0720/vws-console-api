package console

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

const newEndpoint = "https://new-region.example"

// endpointFixture registers pve-test-1 on the daemon at validRegion's endpoint
// and routes the console's region calls by endpoint: the old daemon, which
// oldDown makes unreachable, and the new one.
func endpointFixture(t *testing.T) (e loginEnv, g *store.Registry, app *bytes.Buffer,
	oldDaemon, newDaemon *fakeDaemon, oldDown *bool,
) {
	t.Helper()
	e, g, app, _ = accountFixture(t)
	oldDaemon, newDaemon, oldDown = newFakeDaemon(t), newFakeDaemon(t), new(bool)
	oldEndpoint := validRegion()["regionEndpoint"].(string)
	client := func(endpoint string) *regionapi.Client {
		endpoint = strings.TrimSuffix(endpoint, "/") // the client dials the origin
		switch {
		case endpoint == oldEndpoint && *oldDown:
			return oldDaemon.down
		case endpoint == oldEndpoint:
			return oldDaemon.up
		case endpoint == newEndpoint:
			return newDaemon.up
		}
		t.Fatalf("call to an unknown endpoint %s", endpoint)
		return nil
	}
	h := e.h.(*handler)
	h.regionRegistration = func(ctx context.Context, endpoint string, data json.RawMessage) error {
		return client(endpoint).Register(ctx, data)
	}
	h.regionDeregistration = func(ctx context.Context, endpoint, region string, generation int64) error {
		return client(endpoint).Deregister(ctx, region, generation)
	}
	regionCall(t, e, "POST", validRegion(), "", 201)
	return e, g, app, oldDaemon, newDaemon, oldDown
}

func etag(t *testing.T, g *store.Registry) (store.Region, string) {
	t.Helper()
	v, err := g.Regions().Get(t.Context(), "pve-test-1")
	if err != nil {
		t.Fatal(err)
	}
	return v, strconv.Quote(strconv.FormatInt(int64(v.Version), 10))
}

func moveBody() map[string]any {
	return map[string]any{"regionEndpoint": newEndpoint, "tokenSecret": validRegion()["tokenSecret"]}
}

func patchRegion(t *testing.T, e loginEnv, query string, body map[string]any, match string, want int) string {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rec := e.do(t, "PATCH", regionPath+"/pve-test-1"+query, string(data),
		map[string]string{"Authorization": "Bearer tok", "If-Match": match})
	if rec.Code != want {
		t.Fatalf("PATCH%s: %d %s", query, rec.Code, rec.Body)
	}
	return rec.Body.String()
}

func TestRegionMoveDeregistersTheOldDaemon(t *testing.T) {
	e, g, _, oldDaemon, newDaemon, _ := endpointFixture(t)
	_, match := etag(t, g)
	patchRegion(t, e, "", moveBody(), match, 200)
	removed, registered, pushes := oldDaemon.state()
	if registered || pushes != 1 {
		t.Fatalf("old daemon: registered %v, pushes %d", registered, pushes)
	}
	generation, registered, pushes := newDaemon.state()
	if !registered || pushes != 1 || generation <= removed {
		t.Fatalf("new daemon: registered %v, pushes %d, generation %d after removal %d",
			registered, pushes, generation, removed)
	}
	stored, _ := etag(t, g)
	if stored.RegionEndpoint != newEndpoint || stored.PendingDeregister != nil || stored.LastError != nil {
		t.Fatalf("stored: %+v", stored)
	}
}

// With the old daemon unreachable the move stays pending: the new endpoint
// gets nothing, and a repeat once the old daemon is back completes it.
func TestRegionMoveWaitsForTheOldDaemon(t *testing.T) {
	e, g, _, oldDaemon, newDaemon, oldDown := endpointFixture(t)
	*oldDown = true
	_, match := etag(t, g)
	rec := e.do(t, "PATCH", regionPath+"/pve-test-1", `{"regionEndpoint":"`+newEndpoint+`","tokenSecret":"`+
		validRegion()["tokenSecret"].(string)+`"}`, map[string]string{"Authorization": "Bearer tok", "If-Match": match})
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "repeat the edit") {
		t.Fatalf("PATCH: %d %s", rec.Code, rec.Body)
	}
	stored, retry := etag(t, g)
	if stored.PendingDeregister == nil || stored.PendingDeregister.Endpoint != validRegion()["regionEndpoint"] ||
		rec.Header().Get("ETag") != retry {
		t.Fatalf("pending move: %+v, ETag %q", stored, rec.Header().Get("ETag"))
	}
	if _, registered, _ := oldDaemon.state(); !registered {
		t.Fatal("old daemon lost its registration")
	}
	if _, _, pushes := newDaemon.state(); pushes != 0 {
		t.Fatalf("the new daemon got %d pushes before the old one was told", pushes)
	}
	patchRegion(t, e, "", map[string]any{"zones": []store.Zone{{Letter: "b"}}}, retry, 400) // needs the secrets again
	*oldDown = false
	patchRegion(t, e, "", moveBody(), retry, 200)
	if _, registered, _ := oldDaemon.state(); registered {
		t.Fatal("old daemon still registered")
	}
	if _, registered, pushes := newDaemon.state(); !registered || pushes != 1 {
		t.Fatalf("new daemon: registered %v, pushes %d", registered, pushes)
	}
	if stored, _ := etag(t, g); stored.PendingDeregister != nil {
		t.Fatalf("pending kept: %+v", stored)
	}
}

func TestRegionMoveForcedPastAnUnreachableOldDaemon(t *testing.T) {
	e, g, app, oldDaemon, newDaemon, oldDown := endpointFixture(t)
	*oldDown = true
	generationBefore, _, _ := oldDaemon.state()
	_, match := etag(t, g)
	patchRegion(t, e, "?force=true", moveBody(), match, 200)
	if generation, registered, pushes := oldDaemon.state(); !registered || pushes != 1 || generation != generationBefore {
		t.Fatalf("old daemon changed: generation %d, registered %v, pushes %d", generation, registered, pushes)
	}
	if _, registered, pushes := newDaemon.state(); !registered || pushes != 1 {
		t.Fatalf("new daemon: registered %v, pushes %d", registered, pushes)
	}
	if stored, _ := etag(t, g); stored.RegionEndpoint != newEndpoint || stored.PendingDeregister != nil {
		t.Fatalf("stored: %+v", stored)
	}
	if !strings.Contains(app.String(), "revoke its old token in PVE") {
		t.Fatalf("warning: %s", app)
	}
}

// Every refusal comes before any daemon is touched.
func TestRegionMoveRefusalsTouchNoDaemon(t *testing.T) {
	e, g, _, oldDaemon, newDaemon, _ := endpointFixture(t)
	calls := 0
	h := e.h.(*handler)
	deregister := h.regionDeregistration
	h.regionDeregistration = func(ctx context.Context, endpoint, region string, generation int64) error {
		calls++
		return deregister(ctx, endpoint, region, generation)
	}
	before, match := etag(t, g)
	noToken := map[string]any{"regionEndpoint": newEndpoint}
	if body := patchRegion(t, e, "", noToken, match, 400); !strings.Contains(body, "tokenSecret") {
		t.Fatalf("move without a token: %s", body)
	}
	if err := g.ClaimCluster(t.Context(), "other", "pve-other-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	claimed := moveBody()
	claimed["clusterName"] = "other"
	if body := patchRegion(t, e, "", claimed, match, 400); !strings.Contains(body, "clusterName") {
		t.Fatalf("move to a claimed cluster: %s", body)
	}
	patchRegion(t, e, "", moveBody(), `"1"`, 409)
	patchRegion(t, e, "?force=1", moveBody(), match, 400)
	if after, _ := etag(t, g); after.Version != before.Version || calls != 0 {
		t.Fatalf("a refusal changed the registry (%+v) or reached a daemon (%d)", after, calls)
	}
	if _, registered, pushes := oldDaemon.state(); !registered || pushes != 1 {
		t.Fatalf("old daemon: registered %v, pushes %d", registered, pushes)
	}
	if _, _, pushes := newDaemon.state(); pushes != 0 {
		t.Fatalf("new daemon got %d pushes", pushes)
	}
}

// Two moves at the same version: the one that loses the registry CAS has
// touched no daemon.
func TestRegionMoveOverlapLosesTheCASBeforeAnyDaemon(t *testing.T) {
	e, g, _, oldDaemon, _, _ := endpointFixture(t)
	h := e.h.(*handler)
	_, match := etag(t, g)
	inFirst, resume := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	calls := 0
	deregister := h.regionDeregistration
	h.regionDeregistration = func(ctx context.Context, endpoint, region string, generation int64) error {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			close(inFirst)
			<-resume
		}
		return deregister(ctx, endpoint, region, generation)
	}
	first := make(chan string, 1)
	go func() { first <- patchRegion(t, e, "", moveBody(), match, 200) }()
	awaitSignal(t, inFirst)
	patchRegion(t, e, "", moveBody(), match, 409)
	mu.Lock()
	n := calls
	mu.Unlock()
	if n != 1 {
		t.Fatalf("the losing PATCH reached a daemon: %d calls", n)
	}
	close(resume)
	<-first
	if _, registered, _ := oldDaemon.state(); registered {
		t.Fatal("old daemon still registered")
	}
}

// A trailing slash names the same daemon: it is not a move, and the stored
// token is reused there.
func TestRegionSlashOnlyEditIsNotAMove(t *testing.T) {
	e, g, _, oldDaemon, newDaemon, _ := endpointFixture(t)
	_, match := etag(t, g)
	patchRegion(t, e, "", map[string]any{"regionEndpoint": validRegion()["regionEndpoint"].(string) + "/"}, match, 200)
	if generation, registered, pushes := oldDaemon.state(); !registered || pushes != 2 || generation == 0 {
		t.Fatalf("daemon: registered %v, pushes %d", registered, pushes)
	}
	if _, _, pushes := newDaemon.state(); pushes != 0 {
		t.Fatalf("another daemon got %d pushes", pushes)
	}
}

func TestRegionPatchWithoutAnEndpointChangeTouchesOnlyItsDaemon(t *testing.T) {
	e, g, _, oldDaemon, newDaemon, _ := endpointFixture(t)
	before, match := etag(t, g)
	patchRegion(t, e, "", map[string]any{
		"regionEndpoint": before.RegionEndpoint, "zones": []store.Zone{{Letter: "b"}},
	}, match, 200)
	if _, registered, pushes := oldDaemon.state(); !registered || pushes != 2 {
		t.Fatalf("daemon: registered %v, pushes %d", registered, pushes)
	}
	if _, _, pushes := newDaemon.state(); pushes != 0 {
		t.Fatalf("another daemon got %d pushes", pushes)
	}
}

// A region deleted while a move is pending deregisters the old daemon too,
// which still holds the tokens.
func TestRegionDeleteDuringAPendingMoveTellsTheOldDaemon(t *testing.T) {
	e, g, _, oldDaemon, _, oldDown := endpointFixture(t)
	*oldDown = true
	_, match := etag(t, g)
	patchRegion(t, e, "", moveBody(), match, 503)
	*oldDown = false
	regionCall(t, e, "DELETE", nil, "", 204)
	if _, registered, _ := oldDaemon.state(); registered {
		t.Fatal("old daemon still registered")
	}
}
