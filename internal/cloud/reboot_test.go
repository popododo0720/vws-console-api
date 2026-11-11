package cloud

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestRebootTokensDistinguishLaterRequestsFromReplay(t *testing.T) {
	world := fake.New(fake.Options{Entropy: &fake.Sequence{}})
	svc := New(Config{Backends: world.Set()})
	c := caller(t)
	subnet, err := svc.CreateSubnet(t.Context(), c, token(t, "reboot-subnet"),
		resource.CreateSubnetRequest{Cidr: "10.8.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if len(subnet.Items) != 1 {
		t.Fatalf("CreateSubnet returned %d items, want 1", len(subnet.Items))
	}
	req := runReq(t)
	req.SubnetID = subnet.Items[0].ID
	run, err := svc.RunInstances(t.Context(), c, token(t, "reboot-instance"), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Items) != 1 {
		t.Fatalf("RunInstances returned %d items, want 1", len(run.Items))
	}
	if _, err := svc.GetOperation(t.Context(), c, run.Operation.ID); err != nil {
		t.Fatal(err)
	}
	reboot := resource.RebootInstancesRequest{IDs: []resource.InstanceID{run.Items[0].ID}}
	for _, tc := range []struct {
		name   string
		token  resource.ClientToken
		replay bool
	}{
		{"without a token", resource.ClientToken{}, false},
		{"with a console key", token(t, "console-reboot"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, err := svc.RebootInstances(t.Context(), c, tc.token, reboot)
			if err != nil {
				t.Fatal(err)
			}
			restarted := New(Config{Backends: world.Set()})
			again, err := restarted.RebootInstances(t.Context(), c, tc.token, reboot)
			if err != nil {
				t.Fatal(err)
			}
			if same := first.Operation.ID == again.Operation.ID; same != tc.replay {
				t.Fatalf("same operation = %v, want %v", same, tc.replay)
			}
		})
	}
}
