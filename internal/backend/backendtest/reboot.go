package backendtest

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Reboot checks RebootInstances: a running instance stays running under a
// RebootInstances operation, a retry replays it, and a missing, foreign or
// stopped instance fails the whole request with nothing rebooted.
func Reboot(t *testing.T, newSet Harness) {
	t.Helper()
	ctx := context.Background()
	set := newSet()
	account, other := parse[resource.AccountID](t, "123456789012"), parse[resource.AccountID](t, "210987654321")
	scope := backend.Scope{Account: account}
	mut := func(key string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: "k-reboot-" + key, Fingerprint: "fp-reboot-" + key}
	}
	subnet, err := set.Network.CreateSubnet(ctx, mut("subnet"), resource.CreateSubnetRequest{Cidr: "10.9.0.0/24"})
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
	missing := parse[resource.InstanceID](t, "i-01234567")

	one := resource.RebootInstancesRequest{IDs: []resource.InstanceID{id}}
	rebooted, err := set.Compute.RebootInstances(ctx, mut("one"), one)
	if err != nil || len(rebooted.Items) != 1 || rebooted.Items[0].ID != id ||
		rebooted.Items[0].Previous != resource.InstanceRunning || rebooted.Items[0].Current != resource.InstanceRunning {
		t.Fatalf("reboot: %v %+v", err, rebooted.Items)
	}
	op, err := set.Compute.GetOperation(ctx, scope, rebooted.Operation.ID)
	if err != nil || op.Action != resource.ActionRebootInstances || len(op.Targets) != 1 || op.Targets[0] != id.Ref() {
		t.Fatalf("reboot operation: %v %+v", err, op)
	}
	again, err := set.Compute.RebootInstances(ctx, mut("one"), one)
	if err != nil || again.Operation.ID != rebooted.Operation.ID {
		t.Fatalf("reboot retry: %v %+v", err, again.Operation)
	}
	if got := instanceState(ctx, t, set, scope, id); got != resource.InstanceRunning {
		t.Fatalf("after reboot: %s", got)
	}

	if _, err := set.Compute.RebootInstances(ctx, mut("missing"), resource.RebootInstancesRequest{
		IDs: []resource.InstanceID{idle, missing},
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("reboot with a missing id: %v", err)
	}
	if _, err := set.Compute.RebootInstances(ctx, backend.Mutation{
		Scope: backend.Scope{Account: other}, Key: "k-reboot-foreign", Fingerprint: "fp-reboot-foreign",
	}, resource.RebootInstancesRequest{IDs: []resource.InstanceID{idle}}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("reboot of another account's instance: %v", err)
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
	if _, err := set.Compute.RebootInstances(ctx, mut("stopped"), resource.RebootInstancesRequest{
		IDs: []resource.InstanceID{id, idle},
	}); resource.CodeOf(err) != resource.CodeConflict {
		t.Fatalf("reboot of a stopped instance: %v", err)
	}
	if got := instanceState(ctx, t, set, scope, idle); got != resource.InstanceStopped {
		t.Fatalf("stopped instance after a refused reboot: %s", got)
	}
}

func instanceState(
	ctx context.Context, t *testing.T, set backend.Set, scope backend.Scope, id resource.InstanceID,
) resource.InstanceState {
	t.Helper()
	got, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{
		IDs: []resource.InstanceID{id}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(got.Items) != 1 {
		t.Fatalf("describe %s: %v %+v", id, err, got.Items)
	}
	return got.Items[0].State
}
