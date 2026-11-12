package backendtest

import (
	"context"
	"net/url"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Console checks OpenConsole on a set that offers consoles: a running
// instance of the caller's opens each kind as a websocket session that
// expires, and a missing, foreign or stopped instance or an unknown kind
// opens nothing.
func Console(t *testing.T, newSet Harness) {
	t.Helper()
	ctx := context.Background()
	set := newSet()
	if set.Console == nil {
		t.Fatal("Console is nil: a set without consoles does not run this group")
	}
	account, other := parse[resource.AccountID](t, "123456789012"), parse[resource.AccountID](t, "210987654321")
	scope := backend.Scope{Account: account}
	mut := func(key string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: "k-console-" + key, Fingerprint: "fp-console-" + key}
	}
	subnet, err := set.Network.CreateSubnet(ctx, mut("subnet"), resource.CreateSubnetRequest{Cidr: "10.8.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := set.Compute.RunInstances(ctx, mut("run"), resource.RunInstancesRequest{
		ImageID: parse[resource.ImageID](t, "ami-0123456789abcdef0"), InstanceType: "vws.small",
		SubnetID: subnet.Items[0].ID, Count: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, run.Operation.ID); err != nil {
		t.Fatal(err)
	}
	id, idle := run.Items[0].ID, run.Items[1].ID

	for _, kind := range []resource.ConsoleKind{resource.ConsoleVNC, resource.ConsoleSerial} {
		got, err := set.Console.OpenConsole(ctx, scope, id, kind)
		if err != nil || got.Kind != kind || got.Expires.IsZero() {
			t.Fatalf("open %s: %v %+v", kind, err, got)
		}
		u, err := url.Parse(got.URL)
		if got.Dial == nil && (err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "") {
			t.Fatalf("open %s: url %q is not a websocket address: %v", kind, got.URL, err)
		}
	}

	refusals := []struct {
		name  string
		scope backend.Scope
		id    resource.InstanceID
		kind  resource.ConsoleKind
		want  resource.Code
	}{
		{"missing instance", scope, parse[resource.InstanceID](t, "i-01234567"), resource.ConsoleVNC, resource.CodeNotFound},
		{"another account's instance", backend.Scope{Account: other}, id, resource.ConsoleVNC, resource.CodeNotFound},
		{"no kind", scope, id, resource.ConsoleKind(0), resource.CodeInvalidArgument},
	}
	for _, tc := range refusals {
		if got, err := set.Console.OpenConsole(ctx, tc.scope, tc.id, tc.kind); resource.CodeOf(err) != tc.want {
			t.Fatalf("%s: %v %+v, want %s", tc.name, err, got, tc.want)
		}
	}

	stop, err := set.Compute.StopInstances(ctx, mut("stop"), resource.StopInstancesRequest{
		IDs: []resource.InstanceID{idle},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, stop.Operation.ID); err != nil {
		t.Fatal(err)
	}
	got, err := set.Console.OpenConsole(ctx, scope, idle, resource.ConsoleSerial)
	if resource.CodeOf(err) != resource.CodeConflict {
		t.Fatalf("stopped instance: %v %+v", err, got)
	}
}
