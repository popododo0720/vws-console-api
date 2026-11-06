package grpcclient

import (
	"context"
	"reflect"
	"strings"
	"testing"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestBadReferenceIsSkippedInList(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	ready := commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	running := computev1.InstancePower_INSTANCE_POWER_RUNNING
	const goodInstanceID = "i-0123456789abcdef0"
	const goodVolumeID = "vol-0123456789abcdef0"

	badInstances := map[string]func(*computev1.Instance){
		"i-0000000000000000a": func(in *computev1.Instance) { delete(in.Labels, labelReservation) },
		"i-0000000000000000b": func(in *computev1.Instance) { delete(in.Labels, labelImage) },
		"i-0000000000000000c": func(in *computev1.Instance) { in.Spec.NetworkInterfaces = nil },
		"i-0000000000000000d": func(in *computev1.Instance) { in.Spec.NetworkInterfaces[0].Subnet = "subnets/bad" },
		"i-0000000000000000e": func(in *computev1.Instance) { in.Spec.KeyPair = "keyPairs/bad" },
		"i-0000000000000000f": func(in *computev1.Instance) {
			in.Spec.Volumes = []*computev1.VolumeAttachment{{Volume: "volumes/bad", DeviceName: "/dev/sdf"}}
		},
	}
	badVolumes := map[string]func(*storagev1.Volume){
		"vol-0000000000000000a": func(v *storagev1.Volume) { v.Status.Instance = "instances/bad" },
		"vol-0000000000000000c": func(v *storagev1.Volume) { v.Status.Instance = "instances/" + account.String() },
		"vol-0000000000000000b": func(v *storagev1.Volume) {
			v.Spec.Source = &storagev1.VolumeSpec_Snapshot{Snapshot: "snapshots/bad"}
		},
	}
	world := &invalidNameWorld{
		inst: []*computev1.Instance{observedInstance(projectID, goodInstanceID, ready, running)},
		vol:  []*storagev1.Volume{observedVolume(projectID, goodVolumeID, ready, "")},
	}
	for id, breakIt := range badInstances {
		in := observedInstance(projectID, id, ready, running)
		breakIt(in)
		world.inst = append(world.inst, in)
	}
	for id, breakIt := range badVolumes {
		v := observedVolume(projectID, id, ready, "")
		breakIt(v)
		world.vol = append(world.vol, v)
	}
	client, logs := dialInvalidNameWorld(t, world)
	ctx := context.Background()
	scope := backend.Scope{Account: account}

	instances, err := client.DescribeInstances(ctx, scope, resource.InstanceQuery{})
	if err != nil {
		t.Fatalf("DescribeInstances: %v", err)
	}
	if len(instances.Items) != 1 || instances.Items[0].ID.String() != goodInstanceID {
		t.Fatalf("instances %+v", instances.Items)
	}
	volumes, err := client.DescribeVolumes(ctx, scope, resource.VolumeQuery{})
	if err != nil {
		t.Fatalf("DescribeVolumes: %v", err)
	}
	if len(volumes.Items) != 1 || volumes.Items[0].ID.String() != goodVolumeID {
		t.Fatalf("volumes %+v", volumes.Items)
	}
	for id := range badInstances {
		if !strings.Contains(logs.String(), id) {
			t.Errorf("no log names skipped instance %s: %s", id, logs.String())
		}
	}
	for id := range badVolumes {
		if !strings.Contains(logs.String(), id) {
			t.Errorf("no log names skipped volume %s: %s", id, logs.String())
		}
	}
	if strings.Contains(logs.String(), account.String()) {
		t.Errorf("a skip log carries the account id: %s", logs.String())
	}

	for id := range badInstances {
		parsed, err := resource.Parse[resource.InstanceID](id)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.DescribeInstances(ctx, scope, resource.InstanceQuery{IDs: []resource.InstanceID{parsed}})
		if resource.CodeOf(err) != resource.CodeInternal {
			t.Errorf("explicit read of %s: %v", id, err)
		}
	}
	for id := range badVolumes {
		parsed, err := resource.Parse[resource.VolumeID](id)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.DescribeVolumes(ctx, scope, resource.VolumeQuery{IDs: []resource.VolumeID{parsed}})
		if resource.CodeOf(err) != resource.CodeInternal {
			t.Errorf("explicit read of %s: %v", id, err)
		}
	}
}

// TestSkippedInstanceKeepsItsAttachState lists the volumes of an instance
// with no vws-image label: one compute reports ATTACHED, and one the spec
// names before storage does (#214). They read as they do beside the same
// instance with its label.
func TestSkippedInstanceKeepsItsAttachState(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	ready := commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	const instID = "i-0123456789abcdef0"
	const attachedID = "vol-0123456789abcdef0"
	const pendingID = "vol-0123456789abcdef1"
	list := func(dropImage bool) []resource.Volume {
		inst := observedInstance(projectID, instID, ready, computev1.InstancePower_INSTANCE_POWER_RUNNING)
		if dropImage {
			delete(inst.Labels, labelImage)
		}
		inst.Spec.Volumes = []*computev1.VolumeAttachment{
			{Volume: volumeName(projectID, attachedID), DeviceName: "/dev/sdf"},
			{Volume: volumeName(projectID, pendingID), DeviceName: "/dev/sdg"},
		}
		inst.Status.Volumes = []*computev1.ObservedVolumeAttachment{{
			Volume: volumeName(projectID, attachedID), DeviceName: "/dev/sdf",
			State: computev1.VolumeAttachState_VOLUME_ATTACH_STATE_ATTACHED,
		}}
		world := &invalidNameWorld{
			inst: []*computev1.Instance{inst},
			vol: []*storagev1.Volume{
				observedVolume(projectID, attachedID, ready, instID),
				observedVolume(projectID, pendingID, ready, ""),
			},
		}
		client, _ := dialInvalidNameWorld(t, world)
		volumes, err := client.DescribeVolumes(context.Background(), backend.Scope{Account: account}, resource.VolumeQuery{})
		if err != nil {
			t.Fatalf("DescribeVolumes: %v", err)
		}
		return volumes.Items
	}
	healthy, skipped := list(false), list(true)
	if len(healthy) != 2 || healthy[0].AttachState != resource.AttachmentAttached {
		t.Fatalf("healthy instance volumes %+v", healthy)
	}
	if !reflect.DeepEqual(skipped, healthy) {
		t.Fatalf("skipped instance volumes %+v, want %+v", skipped, healthy)
	}
}
