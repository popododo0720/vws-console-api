package backendtest

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Restart starts one backend world and returns how to connect to it. Each
// call of the returned func is a new process of this service: the set it
// returns shares nothing with an earlier one but what the backend kept.
type Restart func() (connect func() backend.Set)

// RebootAndConsoleAcrossRestart is the restart case of RebootInstances and
// OpenConsole. This process keeps no state, so a restart is a new set over
// the same backend. A reboot accepted before the restart is replayed by the
// same key from the new process as the same operation, not a second reboot,
// and the new process opens a console session to the instance.
func RebootAndConsoleAcrossRestart(t *testing.T, newWorld Restart) {
	t.Helper()
	ctx := context.Background()
	connect := newWorld()
	before := connect()
	scope := backend.Scope{Account: parse[resource.AccountID](t, "123456789012")}
	mut := func(key string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: "k-restart-" + key, Fingerprint: "fp-restart-" + key}
	}
	subnet, err := before.Network.CreateSubnet(ctx, mut("subnet"), resource.CreateSubnetRequest{Cidr: "10.7.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if len(subnet.Items) != 1 {
		t.Fatalf("CreateSubnet returned %d items, want 1", len(subnet.Items))
	}
	run, err := before.Compute.RunInstances(ctx, mut("run"), resource.RunInstancesRequest{
		ImageID: parse[resource.ImageID](t, "ami-0123456789abcdef0"), InstanceType: "vws.small",
		SubnetID: subnet.Items[0].ID, Count: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Items) != 1 {
		t.Fatalf("RunInstances returned %d items, want 1", len(run.Items))
	}
	if _, err := before.Compute.GetOperation(ctx, scope, run.Operation.ID); err != nil {
		t.Fatal(err)
	}
	id := run.Items[0].ID
	req := resource.RebootInstancesRequest{IDs: []resource.InstanceID{id}}
	rebooted, err := before.Compute.RebootInstances(ctx, mut("reboot"), req)
	if err != nil {
		t.Fatal(err)
	}

	after := connect()
	again, err := after.Compute.RebootInstances(ctx, mut("reboot"), req)
	if err != nil || again.Operation.ID != rebooted.Operation.ID {
		t.Fatalf("reboot retried after a restart: %v op %s, want op %s", err, again.Operation.ID, rebooted.Operation.ID)
	}
	if got := instanceState(ctx, t, after, scope, id); got != resource.InstanceRunning {
		t.Fatalf("after a restart: %s", got)
	}
	if after.Console == nil {
		t.Fatal("Console is nil: a set without consoles does not run this group")
	}
	session, err := after.Console.OpenConsole(ctx, scope, id, resource.ConsoleSerial)
	if err != nil || session.Kind != resource.ConsoleSerial || session.URL == "" {
		t.Fatalf("console after a restart: %v %+v", err, session)
	}
}
