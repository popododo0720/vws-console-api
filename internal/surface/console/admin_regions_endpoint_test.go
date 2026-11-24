package console

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
)

const newEndpoint = "https://new-region.example"

// moveFixture registers pve-test-1 and records every daemon call by endpoint.
// fail makes the next registration push fail.
func moveFixture(t *testing.T) (loginEnv, *store.Registry, map[string][]string, *bool) {
	t.Helper()
	e, g, _, _ := accountFixture(t)
	calls := map[string][]string{}
	fail := new(bool)
	h := e.h.(*handler)
	h.regionRegistration = func(_ context.Context, endpoint string, data json.RawMessage) error {
		calls[endpoint] = append(calls[endpoint], string(data))
		if *fail {
			return errors.New("push failed")
		}
		return nil
	}
	h.regionDeregistration = func(_ context.Context, endpoint, _ string, _ int64) error {
		calls[endpoint] = append(calls[endpoint], "deregister")
		return nil
	}
	regionCall(t, e, "POST", validRegion(), "", 201)
	return e, g, calls, fail
}

func currentRegion(t *testing.T, g *store.Registry) (store.Region, string) {
	t.Helper()
	v, err := g.Regions().Get(t.Context(), "pve-test-1")
	if err != nil {
		t.Fatal(err)
	}
	return v, strconv.Quote(strconv.FormatInt(int64(v.Version), 10))
}

// A refused move calls no daemon and leaves the record as it was.
func refuseMove(
	t *testing.T, e loginEnv, g *store.Registry, calls map[string][]string, body map[string]any, want string,
) {
	t.Helper()
	before, match := currentRegion(t, g)
	pushes := len(calls[before.RegionEndpoint])
	rec := regionCall(t, e, "PATCH", body, match, 400)
	if !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("refusal: %s", rec.Body)
	}
	if after, _ := currentRegion(t, g); after.Version != before.Version || after.RegionEndpoint != before.RegionEndpoint {
		t.Fatalf("registry changed: %+v", after)
	}
	if len(calls[before.RegionEndpoint]) != pushes || len(calls[newEndpoint]) != 0 {
		t.Fatalf("a refused move reached a daemon: %v", calls)
	}
}

func TestRegionMoveWithTheSameTokenIsRefused(t *testing.T) {
	e, g, calls, _ := moveFixture(t)
	refuseMove(t, e, g, calls, map[string]any{
		"regionEndpoint": newEndpoint, "tokenSecret": validRegion()["tokenSecret"],
	}, "needs a new token")
}

func TestRegionMoveWithoutSecretsIsRefused(t *testing.T) {
	e, g, calls, _ := moveFixture(t)
	refuseMove(t, e, g, calls, map[string]any{"regionEndpoint": newEndpoint}, "tokenSecret")
	_, match := currentRegion(t, g)
	regionCall(t, e, "PATCH", map[string]any{
		"firewallTokenId": "vws@pve!firewall", "firewallTokenSecret": "firewall-secret",
	}, match, 200)
	refuseMove(t, e, g, calls, map[string]any{
		"regionEndpoint": newEndpoint, "tokenSecret": "another-token-1069",
	}, "firewallTokenSecret")
}

// A rotation whose push failed stores the new fingerprint, while the daemon
// keeps the old token. A same-origin retry without a secret succeeds with that
// old token. A move must still compare against the acknowledged old token.
func TestRegionMoveComparesTheAcknowledgedToken(t *testing.T) {
	e, g, calls, fail := moveFixture(t)
	*fail = true
	_, match := currentRegion(t, g)
	regionCall(t, e, "PATCH", map[string]any{"tokenSecret": "rotated-token-1076"}, match, 200)
	*fail = false
	_, match = currentRegion(t, g)
	regionCall(t, e, "PATCH", map[string]any{"zones": []store.Zone{{Letter: "b"}}}, match, 200)
	if v, _ := currentRegion(t, g); v.LastError != nil || v.TokenSecret != store.DescribeSecret("rotated-token-1076") ||
		v.AckedTokenFingerprint != store.DescribeSecret(validRegion()["tokenSecret"].(string)).Fingerprint {
		t.Fatalf("stored: %+v", v)
	}
	refuseMove(t, e, g, calls, map[string]any{
		"regionEndpoint": newEndpoint, "tokenSecret": validRegion()["tokenSecret"],
	}, "needs a new token")
}

func TestRegionMoveWithoutAnAcknowledgedTokenIsRefused(t *testing.T) {
	e, g, calls, _ := moveFixture(t)
	v, _ := currentRegion(t, g)
	v.AckedTokenFingerprint = ""
	if _, err := g.Regions().Update(t.Context(), v); err != nil {
		t.Fatal(err)
	}
	refuseMove(t, e, g, calls, map[string]any{
		"regionEndpoint": newEndpoint, "tokenSecret": "another-token-1069",
	}, "not acknowledged a token")
}

func TestRegionMoveWithANewTokenPushesOnlyToTheNewDaemon(t *testing.T) {
	e, g, calls, _ := moveFixture(t)
	oldEndpoint := validRegion()["regionEndpoint"].(string)
	_, match := currentRegion(t, g)
	regionCall(t, e, "PATCH", map[string]any{
		"regionEndpoint": newEndpoint, "tokenSecret": "another-token-1069",
	}, match, 200)
	if len(calls[oldEndpoint]) != 1 || len(calls[newEndpoint]) != 1 ||
		!strings.Contains(calls[newEndpoint][0], "another-token-1069") {
		t.Fatalf("calls: %v", calls)
	}
	if stored, _ := currentRegion(t, g); stored.RegionEndpoint != newEndpoint ||
		stored.TokenSecret != store.DescribeSecret("another-token-1069") || stored.LastError != nil ||
		stored.AckedTokenFingerprint != store.DescribeSecret("another-token-1069").Fingerprint {
		t.Fatalf("stored: %+v", stored)
	}
}

// The same origin spelled with a trailing slash or the default port, or kept
// as is, is not a move: the edit reuses the stored token at the same daemon.
func TestRegionEditOfTheSameOriginIsNotAMove(t *testing.T) {
	oldEndpoint := validRegion()["regionEndpoint"].(string)
	same := []string{oldEndpoint, oldEndpoint + "/", oldEndpoint + ":443", "HTTPS://Region.example:443/"}
	for _, endpoint := range same {
		t.Run(endpoint, func(t *testing.T) {
			e, g, calls, _ := moveFixture(t)
			_, match := currentRegion(t, g)
			regionCall(t, e, "PATCH", map[string]any{
				"regionEndpoint": endpoint, "zones": []store.Zone{{Letter: "b"}},
			}, match, 200)
			pushes := 0
			for _, list := range calls {
				for _, call := range list {
					if call == "deregister" {
						t.Fatalf("an edit deregistered a daemon: %v", calls)
					}
					pushes++
				}
			}
			if pushes != 2 || len(calls[newEndpoint]) != 0 {
				t.Fatalf("calls: %v", calls)
			}
		})
	}
}
