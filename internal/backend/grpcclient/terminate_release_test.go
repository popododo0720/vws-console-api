package grpcclient

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"

	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (w *launchWorld) ListAddresses(
	_ context.Context, req *networkv1.ListAddressesRequest,
) (*networkv1.ListAddressesResponse, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if before, _, _ := w.enter("ListAddresses"); before {
		return nil, errDown()
	}
	out := &networkv1.ListAddressesResponse{}
	for _, name := range slices.Sorted(maps.Keys(w.addresses)) {
		if !strings.HasPrefix(name, req.GetParent()+"/") {
			continue
		}
		addr := &networkv1.Address{Name: name, Spec: &networkv1.AddressSpec{}, Status: &networkv1.AddressStatus{}}
		if owner := w.addresses[name]; owner != "" {
			addr.Spec.Association = &networkv1.AddressAssociation{Instance: owner, DeviceName: "nic0"}
			addr.Status.Instance = owner
		}
		out.Addresses = append(out.Addresses, addr)
	}
	return out, nil
}

// UpdateAddress serves the disassociate a terminate sends. It replays a
// request id, so a resent release changes nothing twice.
func (w *launchWorld) UpdateAddress(
	_ context.Context, req *networkv1.UpdateAddressRequest,
) (*longrunningpb.Operation, error) {
	name := req.GetAddress().GetName()
	return w.create("UpdateAddress", req.GetRequestId(), name, func() error {
		if req.GetAddress().GetSpec().GetAssociation() != nil {
			return errDown()
		}
		w.addresses[name] = ""
		return nil
	})
}

func (w *launchWorld) associate(addr, instance string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.addresses[addr] = instance
}

func (w *launchWorld) owner(addr string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.addresses[addr]
}

func (w *launchWorld) madeCount(method string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.made[method]
}

// terminateFixture is one launched instance with an Elastic IP and a
// second address on another instance.
type terminateFixture struct {
	launchFixture
	id          resource.InstanceID
	mine, other string
}

func newTerminate(t *testing.T, key string) terminateFixture {
	t.Helper()
	f := newLaunch(t, key)
	ids, err := f.launch(t, 1)
	if err != nil {
		t.Fatal(err)
	}
	projectID := project(f.m.Account)
	tf := terminateFixture{
		launchFixture: f,
		id:            ids[0],
		mine:          addressName(projectID, "eipalloc-0000000000000000a"),
		other:         addressName(projectID, "eipalloc-0000000000000000b"),
	}
	f.boot.associate(tf.mine, instanceName(projectID, tf.id.String()))
	f.boot.associate(tf.other, instanceName(projectID, "i-0000000000000000f"))
	return tf
}

func (f terminateFixture) terminate() (resource.Accepted[resource.InstanceStateChange], error) {
	f.m.Key = "term-" + f.m.Key
	return f.client.TerminateInstances(context.Background(), f.m, resource.TerminateInstancesRequest{
		IDs: []resource.InstanceID{f.id},
	})
}

// assertReleased checks that the instance, its boot volume and its private
// IP are gone, its address is free, and no other address changed.
func (f terminateFixture) assertReleased(t *testing.T) {
	t.Helper()
	if v, i, ips := f.boot.left(); v != 0 || i != 0 || ips != 0 {
		t.Fatalf("left volumes %d instances %d ips %d, want none", v, i, ips)
	}
	if owner := f.boot.owner(f.mine); owner != "" {
		t.Fatalf("address %s still names %s", f.mine, owner)
	}
	if owner := f.boot.owner(f.other); !strings.HasSuffix(owner, "/i-0000000000000000f") {
		t.Fatalf("another instance's address changed: %q", owner)
	}
	if n := f.boot.madeCount("UpdateAddress"); n != 1 {
		t.Fatalf("address updates %d, want 1", n)
	}
}

// TestTerminateReleasesTheAddressBeforeTheInstance pins #392: TerminateInstances
// disassociates the instance's Elastic IP before DeleteInstance, which
// compute refuses while an address names the instance, and the boot volume
// and private IP go with the instance. An address of another instance is
// left alone.
func TestTerminateReleasesTheAddressBeforeTheInstance(t *testing.T) {
	f := newTerminate(t, "release")
	acc, err := f.terminate()
	if err != nil {
		t.Fatal(err)
	}
	if len(acc.Items) != 1 || acc.Items[0].ID != f.id || acc.Items[0].Current != resource.InstanceShuttingDown {
		t.Fatalf("items %+v", acc.Items)
	}
	f.assertReleased(t)
}

// TestTerminateCutShortIsFinishedByTheRetry pins #392: a terminate that
// fails at any step, or whose release answer is lost as if the process died
// after it, is finished by a retry with the same token. The retry sends the
// same release, which the network service replays.
func TestTerminateCutShortIsFinishedByTheRetry(t *testing.T) {
	cases := []struct {
		name   string
		inject func(w *launchWorld)
	}{
		{"address list", func(w *launchWorld) { w.failAt("ListAddresses", 1, false) }},
		{"release", func(w *launchWorld) { w.failAt("UpdateAddress", 1, false) }},
		{"release lost", func(w *launchWorld) { w.failAt("UpdateAddress", 1, true) }},
		{"instance delete", func(w *launchWorld) { w.failAt("DeleteInstance", 1, false) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTerminate(t, "cut-"+strings.ReplaceAll(tc.name, " ", "-"))
			tc.inject(f.boot)
			if _, err := f.terminate(); resource.CodeOf(err) != resource.CodeUnavailable {
				t.Fatalf("err %v, want unavailable", err)
			}
			if _, i, _ := f.boot.left(); i != 1 {
				t.Fatalf("instances %d after a failed terminate, want 1", i)
			}
			if _, err := f.terminate(); err != nil {
				t.Fatalf("retry: %v", err)
			}
			f.assertReleased(t)
		})
	}
}

// TestTerminateWithoutAnAddressSendsNoRelease pins that an instance with no
// Elastic IP is terminated with no address update.
func TestTerminateWithoutAnAddressSendsNoRelease(t *testing.T) {
	f := newLaunch(t, "bare")
	ids, err := f.launch(t, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.m.Key = "term-bare"
	if _, err := f.client.TerminateInstances(context.Background(), f.m, resource.TerminateInstancesRequest{
		IDs: ids,
	}); err != nil {
		t.Fatal(err)
	}
	if v, i, ips := f.boot.left(); v != 0 || i != 0 || ips != 0 || f.boot.madeCount("UpdateAddress") != 0 {
		t.Fatalf("left %d %d %d, updates %d", v, i, ips, f.boot.madeCount("UpdateAddress"))
	}
}
