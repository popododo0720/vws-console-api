package backendtest

import (
	"context"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// AttachHarness builds a fresh backend set for AttachLifecycle. step moves
// the backend past its settle delay, so accepted operations take effect.
// Until step is called, an accepted attach has not reached the machine.
type AttachHarness func() (set backend.Set, step func())

// AttachLifecycle runs the #214 table. As on EC2, an accepted AttachVolume is
// attaching, the volume is in-use from the accept with its attachment
// attaching, and once the backend has put the disk on the machine the
// attachment is attached. A volume nobody attached stays available. The
// instance's block device for the volume carries the same status (#448).
func AttachLifecycle(t *testing.T, newSet AttachHarness) {
	t.Helper()
	ctx := context.Background()
	set, step := newSet()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	img, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account}
	mut := func(key string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: "k-214-" + key, Fingerprint: "fp-214-" + key}
	}
	settle := func(t *testing.T, id resource.OperationID) {
		t.Helper()
		step()
		op, err := set.Compute.GetOperation(ctx, scope, id)
		if err != nil || op.State != resource.OperationSucceeded {
			t.Fatalf("operation %s: %v %+v", id, err, op)
		}
	}
	sub, err := set.Network.CreateSubnet(ctx, mut("subnet"), resource.CreateSubnetRequest{Cidr: "10.21.4.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	step()
	if _, err := set.Network.GetOperation(ctx, scope, sub.Operation.ID); err != nil {
		t.Fatal(err)
	}
	run, err := set.Compute.RunInstances(ctx, mut("run"), resource.RunInstancesRequest{
		ImageID: img, InstanceType: "vws.small", SubnetID: sub.Items[0].ID, Count: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	settle(t, run.Operation.ID)
	inst := run.Items[0].ID
	var vols []resource.VolumeID
	for _, key := range []string{"vol", "spare"} {
		created, err := set.Compute.CreateVolume(ctx, mut(key), resource.CreateVolumeRequest{
			SizeGiB: 1, Zone: resource.ZoneName, Type: resource.VolumeGP2,
		})
		if err != nil {
			t.Fatal(err)
		}
		settle(t, created.Operation.ID)
		vols = append(vols, created.Items[0].ID)
	}
	vol, spare := vols[0], vols[1]

	req := resource.AttachVolumeRequest{VolumeID: vol, InstanceID: inst, Device: "/dev/sdf"}
	acc, err := set.Compute.AttachVolume(ctx, mut("attach"), req)
	if err != nil {
		t.Fatal(err)
	}
	if got := acc.Items[0]; got.ID != vol || got.State != resource.VolumeInUse || got.InstanceID != inst ||
		got.Device != "/dev/sdf" || got.AttachState != resource.AttachmentAttaching ||
		acc.Operation.Action != resource.ActionAttachVolume {
		t.Fatalf("attach accept: want in-use, attaching on %s /dev/sdf, got %+v (%s)", inst, got, acc.Operation.Action)
	}
	attachTimes(ctx, t, set, scope, acc, inst, vol)

	rows := []struct {
		name    string
		settled bool
		listed  bool
		want    resource.AttachmentStatus
	}{
		{name: "by id before the attach settles", want: resource.AttachmentAttaching},
		{name: "listed before the attach settles", listed: true, want: resource.AttachmentAttaching},
		{name: "by id after the attach settles", settled: true, want: resource.AttachmentAttached},
		{name: "listed after the attach settles", settled: true, listed: true, want: resource.AttachmentAttached},
	}
	stepped := false
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if row.settled && !stepped {
				settle(t, acc.Operation.ID)
				stepped = true
			}
			got := describeVolumes(ctx, t, set, scope, row.listed, vol, spare)
			v, ok := got[vol]
			if !ok {
				t.Fatalf("volume %s missing from %+v", vol, got)
			}
			if v.State != resource.VolumeInUse || v.InstanceID != inst || v.Device != "/dev/sdf" || v.AttachState != row.want {
				t.Fatalf("volume: want in-use, %s on %s /dev/sdf, got state %s, %q on %q %q",
					row.want, inst, v.State, v.AttachState, v.InstanceID, v.Device)
			}
			s, ok := got[spare]
			if !ok || s.State != resource.VolumeAvailable || !s.InstanceID.IsZero() || s.AttachState != "" {
				t.Fatalf("unattached volume: want available with no attachment, got %+v", s)
			}
			page, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{
				IDs: []resource.InstanceID{inst}, Page: resource.PageRequest{Size: 50},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := backend.BindOf(page.Items[0], vol); !ok {
				t.Fatalf("instance block devices %+v, want %s", page.Items[0].BlockDevices, vol)
			}
			// The instance view says the same as the volume view (#448):
			// the data volume is attached only once the attach settles, and
			// the root volume is attached from launch.
			for _, block := range page.Items[0].BlockDevices {
				want := resource.AttachmentAttached
				if block.VolumeID == vol {
					want = row.want
				}
				if block.Status != want {
					t.Fatalf("instance block %s %s: status %q, want %q", block.Device, block.VolumeID, block.Status, want)
				}
			}
		})
	}
	detachLifecycle(ctx, t, set, scope, mut, settle, inst, vol)
}

// detachLifecycle is the detach half of the table (#298): from the accept
// until the operation settles, the volume is in-use and detaching on its
// instance, and the instance lists it as detaching with no bind. After it,
// the volume is available with no attachment.
func detachLifecycle(
	ctx context.Context, t *testing.T, set backend.Set, scope backend.Scope,
	mut func(string) backend.Mutation, settle func(*testing.T, resource.OperationID),
	inst resource.InstanceID, vol resource.VolumeID,
) {
	t.Helper()
	acc, err := set.Compute.DetachVolume(ctx, mut("detach"), resource.DetachVolumeRequest{VolumeID: vol})
	if err != nil {
		t.Fatal(err)
	}
	if got := acc.Items[0]; got.Status != resource.AttachmentDetaching || got.InstanceID != inst ||
		got.Device != "/dev/sdf" {
		t.Fatalf("detach accept: want detaching on %s /dev/sdf, got %+v", inst, got)
	}
	instanceView := func(t *testing.T) resource.Instance {
		t.Helper()
		page, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{
			IDs: []resource.InstanceID{inst}, Page: resource.PageRequest{Size: 50},
		})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("describe instance: %v %+v", err, page.Items)
		}
		return page.Items[0]
	}
	for _, listed := range []bool{false, true} {
		v := describeVolumes(ctx, t, set, scope, listed, vol)[vol]
		if v.State != resource.VolumeInUse || v.InstanceID != inst || v.Device != "/dev/sdf" ||
			v.AttachState != resource.AttachmentDetaching {
			t.Fatalf("volume during detach (listed %t): want in-use, detaching on %s /dev/sdf, got %+v", listed, inst, v)
		}
	}
	during := instanceView(t)
	if _, ok := backend.BindOf(during, vol); ok {
		t.Fatalf("instance still binds %s during detach: %+v", vol, during.BlockDevices)
	}
	if len(during.DetachingDevices) != 1 || during.DetachingDevices[0].VolumeID != vol ||
		during.DetachingDevices[0].Device != "/dev/sdf" || during.DetachingDevices[0].Status != resource.AttachmentDetaching {
		t.Fatalf("instance detaching devices: want %s /dev/sdf detaching, got %+v", vol, during.DetachingDevices)
	}
	// EC2 refuses to delete a volume that is still detaching.
	_, err = set.Compute.DeleteVolume(ctx, mut("delete-detaching"), resource.DeleteVolumeRequest{ID: vol})
	if err == nil || resource.CodeOf(err) != resource.CodeOf(resource.VolumeAttached(vol)) {
		t.Fatalf("delete during detach: %v, want %v", err, resource.VolumeAttached(vol))
	}
	settle(t, acc.Operation.ID)
	for _, listed := range []bool{false, true} {
		v := describeVolumes(ctx, t, set, scope, listed, vol)[vol]
		if v.State != resource.VolumeAvailable || !v.InstanceID.IsZero() || v.Device != "" || v.AttachState != "" {
			t.Fatalf("volume after detach (listed %t): want available with no attachment, got %+v", listed, v)
		}
	}
	if after := instanceView(t); len(after.DetachingDevices) != 0 {
		t.Fatalf("instance after detach still lists %+v", after.DetachingDevices)
	}
}

// describeVolumes reads ids by id, or lists every volume and keeps ids.
func describeVolumes(
	ctx context.Context, t *testing.T, set backend.Set, scope backend.Scope, listed bool, ids ...resource.VolumeID,
) map[resource.VolumeID]resource.Volume {
	t.Helper()
	q := resource.VolumeQuery{IDs: ids, Page: resource.PageRequest{Size: 50}}
	if listed {
		q = resource.VolumeQuery{Page: resource.PageRequest{Size: 1000}}
	}
	page, err := set.Compute.DescribeVolumes(ctx, scope, q)
	if err != nil {
		t.Fatal(err)
	}
	out := map[resource.VolumeID]resource.Volume{}
	for _, v := range page.Items {
		for _, id := range ids {
			if v.ID == id {
				out[id] = v
			}
		}
	}
	return out
}

// attachTimes pins attachTime (#298), "when the attachment initiated": a
// backend records it at the accept on the volume and on its block device
// alike, and the root's at launch, or records none (gRPC until vws-proto#83).
// With none, AttachVolume answers with the operation's create time.
func attachTimes(
	ctx context.Context, t *testing.T, set backend.Set, scope backend.Scope,
	acc resource.Accepted[resource.Volume], inst resource.InstanceID, vol resource.VolumeID,
) {
	t.Helper()
	recorded := acc.Items[0].AttachTime
	if recorded.IsZero() && acc.Operation.CreateTime.IsZero() {
		t.Fatal("attach accept has neither an attach time nor an operation create time")
	}
	for _, listed := range []bool{false, true} {
		if v := describeVolumes(ctx, t, set, scope, listed, vol)[vol]; !v.AttachTime.Equal(recorded) {
			t.Fatalf("volume attach time %v (listed %t), want the accept's %v", v.AttachTime, listed, recorded)
		}
	}
	page, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{
		IDs: []resource.InstanceID{inst}, Page: resource.PageRequest{Size: 50},
	})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("describe instance: %v %+v", err, page.Items)
	}
	for _, block := range page.Items[0].BlockDevices {
		want := page.Items[0].LaunchTime
		if block.VolumeID == vol {
			want = recorded
		}
		if recorded.IsZero() {
			want = time.Time{}
		}
		if !block.AttachTime.Equal(want) {
			t.Fatalf("instance block %s attach time %v, want %v", block.Device, block.AttachTime, want)
		}
	}
}
