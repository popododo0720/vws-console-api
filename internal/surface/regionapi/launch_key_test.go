package regionapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"
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

// The launch's public key crosses the region transport byte for byte, while
// the model's JSON, which the request fingerprint is computed from, never
// carries it. A request without a key is on the wire exactly as before, so a
// daemon without the field still accepts it.
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
	c, _ := loopback(t, config(set))

	plain := resource.RunInstancesRequest{
		ImageID: image, InstanceType: "vws.small", SubnetID: subs.Items[0].ID, Count: 1, KeyName: "login",
	}
	withKey := plain
	withKey.PublicKey = launchKey
	for i, req := range []resource.RunInstancesRequest{withKey, plain} {
		m := backend.Mutation{Scope: scope, Key: "key-" + string(rune('a'+i)), Fingerprint: "f"}
		var out resource.Accepted[resource.Instance]
		if err := c.Call(t.Context(), "Compute", "RunInstances", m, req, &out); err != nil {
			t.Fatal(err)
		}
	}
	if len(keyed.got) != 2 || !reflect.DeepEqual(keyed.got[0], withKey) || !reflect.DeepEqual(keyed.got[1], plain) {
		t.Fatalf("the region received %+v", keyed.got)
	}

	model, err := json.Marshal(withKey)
	if err != nil {
		t.Fatal(err)
	}
	without, err := json.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(encodeRequest(plain))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(model, without) || !bytes.Equal(wire, without) {
		t.Fatalf("the model JSON depends on the key, or a keyless request changed on the wire:\n%s\n%s\n%s",
			model, without, wire)
	}
	if strings.Contains(log.String(), "AAAAC3") {
		t.Fatalf("the key reached the log: %s", log.String())
	}
}
