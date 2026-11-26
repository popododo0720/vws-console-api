package regionapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const launchKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0wmN/Cr3JXqmLW7u+g9pTh+wyqDHpSQEC8lf7xuF2l"

// keyedCompute records the launch request the region backend receives.
type keyedCompute struct {
	backend.Compute
	got []resource.RunInstancesRequest
}

func (c *keyedCompute) RunInstances(
	ctx context.Context, m backend.Mutation, req resource.RunInstancesRequest,
) (resource.Accepted[resource.Instance], error) {
	c.got = append(c.got, req)
	return c.Compute.RunInstances(ctx, m, req)
}

// launchWire records the launch requests a daemon receives. With old set it
// answers the keyed route 404, as a daemon that predates the route does: its
// RunInstances route is the one this daemon still serves.
type launchWire struct {
	mu     sync.Mutex
	old    bool
	paths  []string
	bodies []string
}

func (l *launchWire) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/internal/v1/Compute/RunInstances") {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			l.mu.Lock()
			l.paths, l.bodies = append(l.paths, r.URL.Path), append(l.bodies, string(body))
			old := l.old
			l.mu.Unlock()
			if old && r.URL.Path == "/internal/v1/Compute/"+keyedLaunch {
				http.NotFound(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (l *launchWire) take() ([]string, []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	paths, bodies := l.paths, l.bodies
	l.paths, l.bodies = nil, nil
	return paths, bodies
}

// The launch's public key crosses the region transport byte for byte on its
// own route, while the model's JSON, which the request fingerprint is
// computed from, never carries it. A launch without a key goes to
// RunInstances exactly as before. A daemon that predates the keyed route
// still takes a keyed launch, without the key, so neither upgrade order
// breaks a launch.
func TestRunInstancesCarriesThePublicKey(t *testing.T) {
	var log bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&log, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	set := fake.New(fake.Options{}).Set()
	scope := testScope(t)
	seedReads(t, set, scope)
	subs, err := set.Network.DescribeSubnets(t.Context(), scope,
		resource.SubnetQuery{Page: resource.PageRequest{Size: 100}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.CreateKeyPair(t.Context(), backend.Mutation{Scope: scope, Key: "key", Fingerprint: "key"},
		resource.CreateKeyPairRequest{Name: "login", Type: resource.KeyTypeEd25519}); err != nil {
		t.Fatal(err)
	}
	image, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	keyed := &keyedCompute{Compute: set.Compute}
	set.Compute = keyed
	wire := &launchWire{}
	c, _ := loopback(t, config(set), wire.wrap)

	plain := resource.RunInstancesRequest{
		ImageID: image, InstanceType: "vws.small", SubnetID: subs.Items[0].ID, Count: 1, KeyName: "login",
	}
	withKey := plain
	withKey.PublicKey = launchKey
	model, err := json.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	launches := 0
	launch := func(req resource.RunInstancesRequest) {
		t.Helper()
		launches++
		m := backend.Mutation{Scope: scope, Key: "key-" + string(rune('a'+launches)), Fingerprint: "f"}
		var out resource.Accepted[resource.Instance]
		if err := c.Call(t.Context(), "Compute", "RunInstances", m, req, &out); err != nil || len(out.Items) != 1 {
			t.Fatalf("launch: %v %+v", err, out)
		}
	}

	launch(withKey)
	paths, bodies := wire.take()
	if len(paths) != 1 || paths[0] != "/internal/v1/Compute/"+keyedLaunch ||
		!strings.Contains(bodies[0], `"publicKey":"`+launchKey+`"`) {
		t.Fatalf("keyed launch: %v %v", paths, bodies)
	}
	launch(plain)
	paths, bodies = wire.take()
	if len(paths) != 1 || paths[0] != "/internal/v1/Compute/RunInstances" ||
		!strings.Contains(bodies[0], `"req":`+string(model)+`}`) || strings.Contains(bodies[0], "publicKey") {
		t.Fatalf("a launch without a key changed on the wire: %v %v", paths, bodies)
	}
	if len(keyed.got) != 2 || !reflect.DeepEqual(keyed.got[0], withKey) || !reflect.DeepEqual(keyed.got[1], plain) {
		t.Fatalf("the region received %+v", keyed.got)
	}

	// A daemon that predates the keyed route ran nothing for the 404, and
	// takes the launch on RunInstances without the key.
	wire.mu.Lock()
	wire.old = true
	wire.mu.Unlock()
	launch(withKey)
	paths, bodies = wire.take()
	if len(paths) != 2 || paths[0] != "/internal/v1/Compute/"+keyedLaunch ||
		paths[1] != "/internal/v1/Compute/RunInstances" || strings.Contains(bodies[1], "publicKey") ||
		len(keyed.got) != 3 || !reflect.DeepEqual(keyed.got[2], plain) {
		t.Fatalf("keyed launch on an older daemon: %v %v %+v", paths, bodies, keyed.got)
	}

	wire.mu.Lock()
	wire.old = false
	wire.mu.Unlock()
	var out resource.Accepted[resource.Instance]
	err = c.call(t.Context(), "Compute", keyedLaunch, backend.Mutation{Scope: scope, Key: "empty", Fingerprint: "f"},
		wireRunInstances{plain, ""}, &out)
	if e := resource.AsError(err); e.Code != resource.CodeInvalidArgument || e.Field != "publicKey" ||
		len(keyed.got) != 3 {
		t.Fatalf("the keyed route took a launch without a key: %v", err)
	}

	keyedModel, err := json.Marshal(withKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyedModel, model) {
		t.Fatalf("the model JSON depends on the key:\n%s\n%s", keyedModel, model)
	}
	if strings.Contains(log.String(), "AAAAC3") {
		t.Fatalf("the key reached the log: %s", log.String())
	}
}
