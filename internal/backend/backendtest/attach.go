package backendtest

import (
	"context"
	"testing"

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
