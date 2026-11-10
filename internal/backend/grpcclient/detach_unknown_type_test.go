package grpcclient

import (
	"context"
	"strings"
	"testing"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// #337 AC1: detaching needs no volume type, so an attached volume whose
// stored type this build cannot name (UNSPECIFIED, or a type a later
// vws-proto added) still detaches over gRPC instead of answering Internal.
func TestDetachVolumeWithUnknownTypeDetaches(t *testing.T) {
	for _, typ := range []storagev1.VolumeType{
		storagev1.VolumeType_VOLUME_TYPE_UNSPECIFIED, storagev1.VolumeType(99),
	} {
		t.Run(typ.String(), func(t *testing.T) {
			account := mustAccount(t)
			projectID := project(account)
			const (
				instID = "i-0123456789abcdef0"
				rootID = "vol-0123456789abcdef0"
				dataID = "vol-0fedcba9876543210"
			)
			holder := observedInstance(projectID, instID,
				commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
				computev1.InstancePower_INSTANCE_POWER_RUNNING)
			holder.Spec.Volumes = []*computev1.VolumeAttachment{
				{Volume: volumeName(projectID, rootID), DeviceName: "boot", Boot: true},
				{Volume: volumeName(projectID, dataID), DeviceName: "/dev/sdf"},
			}
			vol := observedVolume(projectID, dataID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, instID)
			vol.Status.DeviceName = "/dev/sdf"
			vol.Spec.Type = typ
			world := &detachWorld{
				inst:      []*computev1.Instance{holder},
				vol:       vol,
				byRequest: map[string]*detachRecord{},
			}
			client := dialDetachWorld(t, world)
			data, err := resource.Parse[resource.VolumeID](dataID)
			if err != nil {
				t.Fatal(err)
			}
			holderID, err := resource.Parse[resource.InstanceID](instID)
			if err != nil {
				t.Fatal(err)
			}
			mut := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-detach", Fingerprint: "fp-detach"}
			detached, err := client.DetachVolume(context.Background(), mut, resource.DetachVolumeRequest{VolumeID: data})
			if err != nil {
				t.Fatalf("DetachVolume: %v", err)
			}
			if item := detached.Items[0]; item.Status != resource.AttachmentDetaching ||
				item.InstanceID != holderID || item.Device != "/dev/sdf" {
				t.Fatalf("detach %+v", item)
			}
			vols := world.volumeNames(instanceName(projectID, instID))
			if len(vols) != 1 || vols[0] != volumeName(projectID, rootID) {
				t.Fatalf("volumes after detach %v", vols)
			}
		})
	}
}

// DetachVolume reads no tags, so a volume whose vws-tags- chunk labels do
// not decode still detaches over gRPC instead of answering Internal.
func TestDetachVolumeWithUndecodableTagsDetaches(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const (
		instID = "i-0123456789abcdef0"
		rootID = "vol-0123456789abcdef0"
		dataID = "vol-0fedcba9876543210"
	)
	holder := observedInstance(projectID, instID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		computev1.InstancePower_INSTANCE_POWER_RUNNING)
	holder.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, rootID), DeviceName: "boot", Boot: true},
		{Volume: volumeName(projectID, dataID), DeviceName: "/dev/sdf"},
	}
	vol := observedVolume(projectID, dataID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, instID)
	vol.Status.DeviceName = "/dev/sdf"
	if vol.Labels == nil {
		vol.Labels = map[string]string{}
	}
	vol.Labels[tagChunkKey(1)] = `{"a":"b"}` // chunk 01 with no chunk 00
	if _, err := volumeModel(vol); resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("volumeModel of undecodable tags: %v, want Internal", err)
	}
	world := &detachWorld{
		inst:      []*computev1.Instance{holder},
		vol:       vol,
		byRequest: map[string]*detachRecord{},
	}
	client := dialDetachWorld(t, world)
	data, err := resource.Parse[resource.VolumeID](dataID)
	if err != nil {
		t.Fatal(err)
	}
	mut := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-detach-tags", Fingerprint: "fp-detach-tags"}
	detached, err := client.DetachVolume(context.Background(), mut, resource.DetachVolumeRequest{VolumeID: data})
	if err != nil {
		t.Fatalf("DetachVolume: %v", err)
	}
	if item := detached.Items[0]; item.Status != resource.AttachmentDetaching || item.Device != "/dev/sdf" {
		t.Fatalf("detach %+v", item)
	}
}

// A volume whose tag labels do not decode still takes calls that read no
// tags (ModifyVolume and DeleteVolume reach storage), while a read of its
// tags by id stays Internal, as for an instance (#568).
func TestUndecodableVolumeTagsBlockOnlyTagReads(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const badID = "vol-0fedcba9876543210"
	bad := observedVolume(projectID, badID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, "")
	bad.Labels = map[string]string{tagChunkKey(1): `{"a":"b"}`} // chunk 01 with no chunk 00
	client := dialDetachWorld(t, &detachWorld{vol: bad, byRequest: map[string]*detachRecord{}})
	id, err := resource.Parse[resource.VolumeID](badID)
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account}
	_, err = client.DescribeVolumes(context.Background(), scope,
		resource.VolumeQuery{IDs: []resource.VolumeID{id}, Page: resource.PageRequest{Size: 5}})
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("DescribeVolumes by id: %v, want Internal", err)
	}
	_, err = client.ModifyVolume(context.Background(),
		backend.Mutation{Scope: scope, Key: "k-mod", Fingerprint: "fp-mod"},
		resource.ModifyVolumeRequest{ID: id, SizeGiB: 16})
	// This world serves no UpdateVolume or DeleteVolume, so reaching storage
	// shows up as that RPC being unimplemented.
	if err == nil || !strings.Contains(err.Error(), "UpdateVolume") {
		t.Fatalf("ModifyVolume did not reach storage's UpdateVolume: %v", err)
	}
	_, err = client.DeleteVolume(context.Background(),
		backend.Mutation{Scope: scope, Key: "k-del", Fingerprint: "fp-del"},
		resource.DeleteVolumeRequest{ID: id})
	if err == nil || !strings.Contains(err.Error(), "DeleteVolume") {
		t.Fatalf("DeleteVolume did not reach storage's DeleteVolume: %v", err)
	}
}
