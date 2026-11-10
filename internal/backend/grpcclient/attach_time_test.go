package grpcclient

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// withoutAttachTime serves instances as a vws-compute from before
// vws-compute#166 does: with no attach_time on the spec or the status.
func withoutAttachTime(
	ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	resp, err := handler(ctx, req)
	var items []*computev1.Instance
	switch msg := resp.(type) {
	case *computev1.Instance:
		items = []*computev1.Instance{msg}
	case *computev1.ListInstancesResponse:
		items = msg.GetInstances()
	}
	for _, inst := range items {
		for _, v := range inst.GetSpec().GetVolumes() {
			v.AttachTime = nil
		}
		for _, v := range inst.GetStatus().GetVolumes() {
			v.AttachTime = nil
		}
	}
	return resp, err
}

// TestAttachTimeIsComputesAttachTime pins where attachTime comes from over
// gRPC (#518): compute's attach_time on the spec entry or the status entry,
// on DescribeVolumes, DescribeInstances, AttachVolume and DetachVolume alike.
// A compute that sends none leaves it zero, so each surface shows its
// stand-in, and DetachVolume answers with the instance launch time.
func TestAttachTimeIsComputesAttachTime(t *testing.T) {
	for _, older := range []bool{false, true} {
		name := "compute sends attach_time"
		if older {
			name = "older compute sends no attach_time"
		}
		t.Run(name, func(t *testing.T) {
			start := time.Unix(1_700_000_000, 0).UTC()
			var offset atomic.Int64
			world := fake.New(fake.Options{
				Now:     func() time.Time { return start.Add(time.Duration(offset.Load())) },
				Latency: time.Second,
				Entropy: &fake.Sequence{},
			})
			var interceptors []grpc.UnaryServerInterceptor
			if older {
				interceptors = append(interceptors, withoutAttachTime)
			}
			set := dialLoopbackClock(t, world, start, nil, interceptors...)()
			step := func() { offset.Add(int64(time.Hour)) }
			checkAttachTimes(t, world, set, step, older)
		})
	}
}

func checkAttachTimes(t *testing.T, world *fake.World, set backend.Set, step func(), older bool) {
	t.Helper()
	ctx := context.Background()
	scope := backend.Scope{Account: mustAccount(t)}
	mut := func(key string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: "k-518-" + key, Fingerprint: "fp-518-" + key}
	}
	settle := func(id resource.OperationID) {
		t.Helper()
		step()
		if op, err := set.Compute.GetOperation(ctx, scope, id); err != nil || op.State != resource.OperationSucceeded {
			t.Fatalf("operation %s: %v %+v", id, err, op)
		}
	}
	sub, err := set.Network.CreateSubnet(ctx, mut("subnet"), resource.CreateSubnetRequest{Cidr: "10.21.5.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	step()
	img, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	run, err := set.Compute.RunInstances(ctx, mut("run"), resource.RunInstancesRequest{
		ImageID: img, InstanceType: "vws.small", SubnetID: sub.Items[0].ID, Count: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	settle(run.Operation.ID)
	inst := run.Items[0].ID
	created, err := set.Compute.CreateVolume(ctx, mut("vol"), resource.CreateVolumeRequest{
		SizeGiB: 1, Zone: resource.ZoneName, Type: resource.VolumeGP2,
	})
	if err != nil {
		t.Fatal(err)
	}
	settle(created.Operation.ID)
	vol := created.Items[0].ID
	step()

	acc, err := set.Compute.AttachVolume(ctx, mut("attach"), resource.AttachVolumeRequest{
		VolumeID: vol, InstanceID: inst, Device: "/dev/sdf",
	})
	if err != nil {
		t.Fatal(err)
	}
	recorded := fakeVolume(ctx, t, world, scope, vol).AttachTime
	launched := describeInstance(ctx, t, set, scope, inst).LaunchTime
	if recorded.IsZero() || launched.IsZero() || recorded.Equal(launched) || recorded.Equal(acc.Operation.CreateTime) {
		t.Fatalf("attach at %v, launch at %v, accept at %v: want three apart", recorded, launched, acc.Operation.CreateTime)
	}
	want, wantRoot, wantDetach := recorded, launched, recorded
	if older {
		want, wantRoot, wantDetach = time.Time{}, time.Time{}, launched
	}
	if got := acc.Items[0].AttachTime; !got.Equal(want) {
		t.Fatalf("AttachVolume attach time %v, want %v", got, want)
	}
	check := func(when string, detaching bool) {
		t.Helper()
		for _, listed := range []bool{false, true} {
			q := resource.VolumeQuery{IDs: []resource.VolumeID{vol}, Page: resource.PageRequest{Size: 50}}
			if listed {
				q = resource.VolumeQuery{Page: resource.PageRequest{Size: 50}}
			}
			page, err := set.Compute.DescribeVolumes(ctx, scope, q)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range page.Items {
				if v.ID == vol && !v.AttachTime.Equal(want) {
					t.Fatalf("%s: DescribeVolumes (listed %t) attach time %v, want %v", when, listed, v.AttachTime, want)
				}
			}
		}
		got := describeInstance(ctx, t, set, scope, inst)
		blocks := got.BlockDevices
		if detaching {
			blocks = append(blocks, got.DetachingDevices...)
		}
		seen := false
		for _, b := range blocks {
			w := wantRoot
			if b.VolumeID == vol {
				w, seen = want, true
			}
			if !b.AttachTime.Equal(w) {
				t.Fatalf("%s: block %s attach time %v, want %v", when, b.Device, b.AttachTime, w)
			}
		}
		if !seen {
			t.Fatalf("%s: instance has no block for %s: %+v", when, vol, got)
		}
	}
	check("attaching", false)
	settle(acc.Operation.ID)
	check("attached", false)

	detach, err := set.Compute.DetachVolume(ctx, mut("detach"), resource.DetachVolumeRequest{VolumeID: vol})
	if err != nil {
		t.Fatal(err)
	}
	if got := detach.Items[0].AttachTime; !got.Equal(wantDetach) {
		t.Fatalf("DetachVolume attach time %v, want %v", got, wantDetach)
	}
	check("detaching", true)
}

func fakeVolume(
	ctx context.Context, t *testing.T, world *fake.World, scope backend.Scope, id resource.VolumeID,
) resource.Volume {
	t.Helper()
	page, err := world.Set().Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{
		IDs: []resource.VolumeID{id}, Page: resource.PageRequest{Size: 1},
	})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("fake volume %s: %v %+v", id, err, page.Items)
	}
	return page.Items[0]
}

func describeInstance(
	ctx context.Context, t *testing.T, set backend.Set, scope backend.Scope, id resource.InstanceID,
) resource.Instance {
	t.Helper()
	page, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{
		IDs: []resource.InstanceID{id}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("describe instance %s: %v %+v", id, err, page.Items)
	}
	return page.Items[0]
}

// failReadAfterUpdate fails the first GetInstance after each UpdateInstance,
// as a compute that accepts a write and then cannot be read.
type failReadAfterUpdate struct{ armed atomic.Bool }

func (f *failReadAfterUpdate) intercept(
	ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	switch req.(type) {
	case *computev1.GetInstanceRequest:
		if f.armed.Swap(false) {
			return nil, status.Error(codes.Unavailable, "compute unavailable")
		}
	case *computev1.UpdateInstanceRequest:
		resp, err := handler(ctx, req)
		f.armed.Store(err == nil)
		return resp, err
	}
	return handler(ctx, req)
}

// TestAttachStandsWhenItsAttachTimeIsUnread pins that a compute read failing
// after the attach was accepted does not fail AttachVolume: the accept
// carries no attach time, so the surface shows its stand-in, and a later
// read gives compute's attach_time.
func TestAttachStandsWhenItsAttachTimeIsUnread(t *testing.T) {
	start := time.Unix(1_700_000_000, 0).UTC()
	world := fake.New(fake.Options{Now: func() time.Time { return start }, Entropy: &fake.Sequence{}})
	fail := &failReadAfterUpdate{}
	set := dialLoopbackClock(t, world, start, nil, fail.intercept)()
	ctx := context.Background()
	scope := backend.Scope{Account: mustAccount(t)}
	mut := func(key string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: "k-518u-" + key, Fingerprint: "fp-518u-" + key}
	}
	sub, err := set.Network.CreateSubnet(ctx, mut("subnet"), resource.CreateSubnetRequest{Cidr: "10.21.6.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	img, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	run, err := set.Compute.RunInstances(ctx, mut("run"), resource.RunInstancesRequest{
		ImageID: img, InstanceType: "vws.small", SubnetID: sub.Items[0].ID, Count: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := set.Compute.CreateVolume(ctx, mut("vol"), resource.CreateVolumeRequest{
		SizeGiB: 1, Zone: resource.ZoneName, Type: resource.VolumeGP2,
	})
	if err != nil {
		t.Fatal(err)
	}
	vol := created.Items[0].ID
	fail.armed.Store(false)
	acc, err := set.Compute.AttachVolume(ctx, mut("attach"), resource.AttachVolumeRequest{
		VolumeID: vol, InstanceID: run.Items[0].ID, Device: "/dev/sdf",
	})
	if err != nil {
		t.Fatalf("AttachVolume with an unreadable compute after the accept: %v", err)
	}
	if got := acc.Items[0].AttachTime; !got.IsZero() || acc.Items[0].AttachState != resource.AttachmentAttaching {
		t.Fatalf("accept %+v, want attaching with no attach time", acc.Items[0])
	}
	recorded := fakeVolume(ctx, t, world, scope, vol).AttachTime
	page, err := set.Compute.DescribeVolumes(ctx, scope, resource.VolumeQuery{
		IDs: []resource.VolumeID{vol}, Page: resource.PageRequest{Size: 1},
	})
	if err != nil || len(page.Items) != 1 || recorded.IsZero() || !page.Items[0].AttachTime.Equal(recorded) {
		t.Fatalf("describe after the accept: %v %+v, want attach time %v", err, page.Items, recorded)
	}
}
