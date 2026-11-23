package console

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

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

func TestRegionEndpointChangeDeregistersTheOldDaemon(t *testing.T) {
	e, g, _, oldDaemon, newDaemon, _ := endpointFixture(t)
	_, match := etag(t, g)
	regionCall(t, e, "PATCH", map[string]any{
		"regionEndpoint": newEndpoint, "tokenSecret": validRegion()["tokenSecret"],
	}, match, 200)
	if _, registered, pushes := oldDaemon.state(); registered || pushes != 1 {
		t.Fatalf("old daemon: registered %v, pushes %d", registered, pushes)
	}
	removed, _, _ := oldDaemon.state()
	generation, registered, pushes := newDaemon.state()
	if !registered || pushes != 1 || generation <= removed {
		t.Fatalf("new daemon: registered %v, pushes %d, generation %d after removal %d",
			registered, pushes, generation, removed)
	}
	stored, _ := etag(t, g)
	if stored.RegionEndpoint != newEndpoint || stored.LastError != nil {
		t.Fatalf("stored: %+v", stored)
	}
}

func TestRegionEndpointChangeWithTheSameTokenNeedsTheOldDaemon(t *testing.T) {
	e, g, _, oldDaemon, newDaemon, oldDown := endpointFixture(t)
	*oldDown = true
	before, match := etag(t, g)
	for _, body := range []map[string]any{
		{"regionEndpoint": newEndpoint},
		{"regionEndpoint": newEndpoint, "tokenSecret": validRegion()["tokenSecret"]},
	} {
		rec := regionCall(t, e, "PATCH", body, match, 400)
		if !strings.Contains(rec.Body.String(), "regionEndpoint") || !strings.Contains(rec.Body.String(), "new tokenSecret") {
			t.Fatalf("refusal: %s", rec.Body)
		}
	}
	if after, _ := etag(t, g); after.Version != before.Version || after.RegionEndpoint != before.RegionEndpoint {
		t.Fatalf("registry changed: %+v", after)
	}
	if _, registered, _ := oldDaemon.state(); !registered {
		t.Fatal("old daemon lost its registration")
	}
	if _, _, pushes := newDaemon.state(); pushes != 0 {
		t.Fatalf("the new daemon got %d pushes", pushes)
	}
}

func TestRegionEndpointChangeWithANewTokenSkipsAnUnreachableOldDaemon(t *testing.T) {
	e, g, app, oldDaemon, newDaemon, oldDown := endpointFixture(t)
	*oldDown = true
	generationBefore, _, _ := oldDaemon.state()
	_, match := etag(t, g)
	const token = "distinctive-new-token-1069"
	regionCall(t, e, "PATCH", map[string]any{"regionEndpoint": newEndpoint, "tokenSecret": token}, match, 200)
	if generation, registered, pushes := oldDaemon.state(); !registered || pushes != 1 || generation != generationBefore {
		t.Fatalf("old daemon was reached: generation %d, registered %v, pushes %d", generation, registered, pushes)
	}
	newDaemon.mu.Lock()
	pushed := newDaemon.registered && len(newDaemon.pushes) == 1 && bytes.Contains(newDaemon.pushes[0], []byte(token))
	newDaemon.mu.Unlock()
	if !pushed {
		t.Fatal("the new daemon did not get the new token")
	}
	if stored, _ := etag(t, g); stored.RegionEndpoint != newEndpoint || stored.TokenSecret != store.DescribeSecret(token) {
		t.Fatalf("stored: %+v", stored)
	}
	if !strings.Contains(app.String(), "revoke them in PVE") || strings.Contains(app.String(), token) {
		t.Fatalf("warning: %s", app)
	}
}

func TestRegionPatchWithoutAnEndpointChangeTouchesOnlyItsDaemon(t *testing.T) {
	e, g, _, oldDaemon, newDaemon, _ := endpointFixture(t)
	before, match := etag(t, g)
	regionCall(t, e, "PATCH", map[string]any{
		"regionEndpoint": before.RegionEndpoint, "zones": []store.Zone{{Letter: "b"}},
	}, match, 200)
	if _, registered, pushes := oldDaemon.state(); !registered || pushes != 2 {
		t.Fatalf("daemon: registered %v, pushes %d", registered, pushes)
	}
	if _, _, pushes := newDaemon.state(); pushes != 0 {
		t.Fatalf("another daemon got %d pushes", pushes)
	}
}
