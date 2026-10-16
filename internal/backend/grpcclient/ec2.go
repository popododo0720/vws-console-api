package grpcclient

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"maps"
	"strconv"
	"strings"
	"time"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sshkey"
)

func (c computeClient) StartInstances(ctx context.Context, m backend.Mutation, req resource.StartInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	return c.changeInstances(ctx, m, req.IDs, resource.ActionStartInstances, computev1.InstancePower_INSTANCE_POWER_RUNNING)
}

func (c computeClient) TerminateInstances(ctx context.Context, m backend.Mutation, req resource.TerminateInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	projectID := project(m.Account)
	prev := make([]resource.Instance, 0, len(req.IDs))
	for _, id := range req.IDs {
		inst, err := c.getInstance(ctx, projectID, id.String())
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		if _, _, err := resource.NextInstanceState(resource.ActionTerminateInstances, inst.State); err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		prev = append(prev, inst)
	}
	var op resource.Operation
	items := make([]resource.InstanceStateChange, 0, len(prev))
	for i, inst := range prev {
		mid, _, err := resource.NextInstanceState(resource.ActionTerminateInstances, inst.State)
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		deleted, err := c.instances.DeleteInstance(ctx, &computev1.DeleteInstanceRequest{
			Name:      instanceName(projectID, inst.ID.String()),
			RequestId: requestUUID(m.Key, "terminate", hex.EncodeToString([]byte{byte(i)})),
		})
		if err := rpcErr(deleted, err); err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		if i == 0 {
			op, err = operationFrom(deleted, resource.ServiceCompute)
			if err != nil {
				return resource.Accepted[resource.InstanceStateChange]{}, err
			}
		}
		items = append(items, resource.InstanceStateChange{
			ID: inst.ID, OwnerID: inst.OwnerID, Previous: inst.State, Current: mid,
		})
	}
	op.Action = resource.ActionTerminateInstances
	op.Targets = stateRefs(items)
	return resource.Accepted[resource.InstanceStateChange]{Operation: op, Items: items}, nil
}

// CreateTags rewrites each instance's labels with the merged tags. Compute
// serves a labels-only UpdateInstance, so power and spec do not change.
func (c computeClient) CreateTags(ctx context.Context, m backend.Mutation, req resource.CreateTagsRequest) (resource.Accepted[resource.Instance], error) {
	projectID := project(m.Account)
	insts := make([]resource.Instance, 0, len(req.IDs))
	for _, id := range req.IDs {
		inst, err := c.getInstance(ctx, projectID, id.String())
		if err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
		if inst.Tags, err = resource.MergeTags(inst.Tags, req.Tags); err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
		insts = append(insts, inst)
	}
	var op resource.Operation
	targets := make([]resource.Ref, 0, len(insts))
	for i, inst := range insts {
		labels, err := withInternalLabels(inst.Tags, map[string]string{
			labelAction:      resource.ActionCreateTags.String(),
			labelFingerprint: clip(m.Fingerprint, 63),
			labelImage:       inst.ImageID.String(),
			labelReservation: inst.ReservationID.String(),
		})
		if err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
		updated, err := c.instances.UpdateInstance(ctx, &computev1.UpdateInstanceRequest{
			RequestId:  requestUUID(m.Key, "tags", hex.EncodeToString([]byte{byte(i)})),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}},
			Instance:   &computev1.Instance{Name: instanceName(projectID, inst.ID.String()), Labels: labels},
		})
		if err := rpcErr(updated, err); err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
		if i == 0 {
			if op, err = operationFrom(updated, resource.ServiceCompute); err != nil {
				return resource.Accepted[resource.Instance]{}, err
			}
		}
		targets = append(targets, inst.ID.Ref())
	}
	op.Action = resource.ActionCreateTags
	op.Targets = targets
	return resource.Accepted[resource.Instance]{Operation: op, Items: insts}, nil
}

func (c computeClient) changeInstances(ctx context.Context, m backend.Mutation, ids []resource.InstanceID, action resource.Action, power computev1.InstancePower) (resource.Accepted[resource.InstanceStateChange], error) {
	projectID := project(m.Account)
	prev := make([]resource.Instance, 0, len(ids))
	for _, id := range ids {
		inst, err := c.getInstance(ctx, projectID, id.String())
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		if _, _, err := resource.NextInstanceState(action, inst.State); err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		prev = append(prev, inst)
	}
	var op resource.Operation
	items := make([]resource.InstanceStateChange, 0, len(prev))
	for i, inst := range prev {
		mid, _, err := resource.NextInstanceState(action, inst.State)
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		labels, err := withInternalLabels(inst.Tags, map[string]string{
			labelAction:      action.String(),
			labelFingerprint: clip(m.Fingerprint, 63),
			labelImage:       inst.ImageID.String(),
			labelReservation: inst.ReservationID.String(),
		})
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		updated, err := c.instances.UpdateInstance(ctx, &computev1.UpdateInstanceRequest{
			RequestId:  requestUUID(m.Key, action.String(), hex.EncodeToString([]byte{byte(i)})),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.power", "labels"}},
			Instance: &computev1.Instance{
				Name:   instanceName(projectID, inst.ID.String()),
				Labels: labels,
				Spec: &computev1.InstanceSpec{
					MachineType: inst.InstanceType,
					Power:       power,
					NetworkInterfaces: []*computev1.NetworkInterface{{
						DeviceName: "nic0",
						Subnet:     subnetName(projectID, "", inst.SubnetID.String()),
					}},
				},
			},
		})
		if err := rpcErr(updated, err); err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		if i == 0 {
			op, err = operationFrom(updated, resource.ServiceCompute)
			if err != nil {
				return resource.Accepted[resource.InstanceStateChange]{}, err
			}
		}
		items = append(items, resource.InstanceStateChange{
			ID: inst.ID, OwnerID: inst.OwnerID, Previous: inst.State, Current: mid,
		})
	}
	op.Action = action
	op.Targets = stateRefs(items)
	return resource.Accepted[resource.InstanceStateChange]{Operation: op, Items: items}, nil
}

func (c computeClient) CreateVolume(ctx context.Context, m backend.Mutation, req resource.CreateVolumeRequest) (resource.Accepted[resource.Volume], error) {
	projectID := project(m.Account)
	spec := &storagev1.VolumeSpec{SizeGib: req.SizeGiB, Type: storageType(req.Type)}
	if !req.SnapshotID.IsZero() {
		// A size of 0 is the snapshot size, which only the snapshot knows.
		snap, err := c.getSnapshot(ctx, projectID, req.SnapshotID.String())
		if err != nil {
			return resource.Accepted[resource.Volume]{}, err
		}
		if req.SizeGiB == 0 {
			req.SizeGiB = snap.VolumeSize
			spec.SizeGib = snap.VolumeSize
		}
		if req.SizeGiB < snap.VolumeSize {
			return resource.Accepted[resource.Volume]{}, resource.Invalid("size", "smaller than the snapshot")
		}
		spec.Source = &storagev1.VolumeSpec_Snapshot{Snapshot: snapshotName(projectID, req.SnapshotID.String())}
	}
	created, err := c.volumes.CreateVolume(ctx, &storagev1.CreateVolumeRequest{
		Parent:    volumeParent(projectID),
		VolumeId:  derivedID("vol-", m.Key, "blank"),
		RequestId: requestUUID(m.Key, "blank-vol"),
		Volume: &storagev1.Volume{
			Labels: map[string]string{labelFingerprint: clip(m.Fingerprint, 63)},
			Spec:   spec,
		},
	})
	if err := rpcErr(created, err); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	return acceptedVolume(created, req, resource.VolumeCreating)
}

func (c computeClient) AttachVolume(ctx context.Context, m backend.Mutation, req resource.AttachVolumeRequest) (resource.Accepted[resource.Volume], error) {
	var zero resource.Accepted[resource.Volume]
	projectID := project(m.Account)
	vol, err := c.getVolume(ctx, projectID, req.VolumeID.String())
	if err != nil {
		return zero, err
	}
	// Attach and detach share one instance spec. The etag is the compare-and-swap.
	for attempt := 0; attempt < 5; attempt++ {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		acc, err := c.attachOnce(ctx, m, projectID, vol, req)
		if !errors.Is(err, etagMismatchError{}) {
			return acc, err
		}
	}
	return zero, resource.Conflict(resource.KindVolume, vol.ID.String(), "instance changed")
}

func (c computeClient) attachOnce(
	ctx context.Context, m backend.Mutation, projectID string, vol resource.Volume, req resource.AttachVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	var zero resource.Accepted[resource.Volume]
	instName := instanceName(projectID, req.InstanceID.String())
	inst, err := c.instances.GetInstance(ctx, &computev1.GetInstanceRequest{Name: instName})
	if err != nil {
		return zero, fromNamedRPC(instName, err)
	}
	model, err := instanceModel(inst)
	if err != nil {
		return zero, err
	}
	volumes := make([]*computev1.VolumeAttachment, 0, len(inst.GetSpec().GetVolumes())+1)
	present := false
	for _, v := range inst.GetSpec().GetVolumes() {
		volumes = append(volumes, v)
		if lastSegment(v.GetVolume()) == req.VolumeID.String() {
			present = true
		}
	}
	if !present {
		volumes = append(volumes, &computev1.VolumeAttachment{
			Volume:     volumeName(projectID, req.VolumeID.String()),
			DeviceName: req.Device,
		})
	}
	labels, err := instanceUpdateLabels(model, inst.GetLabels(), resource.ActionAttachVolume, m.Fingerprint, nil)
	if err != nil {
		return zero, err
	}
	updated, callErr := c.instances.UpdateInstance(ctx, &computev1.UpdateInstanceRequest{
		RequestId:  requestUUID(m.Key, "attach"),
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.volumes", "labels"}},
		Instance: &computev1.Instance{
			Name:   instName,
			Etag:   inst.GetEtag(),
			Labels: labels,
			Spec:   &computev1.InstanceSpec{Volumes: volumes},
		},
	})
	if etagMismatch(callErr) {
		return zero, etagMismatchError{}
	}
	if err := rpcErr(updated, callErr); err != nil {
		return zero, err
	}
	op, err := operationFrom(updated, resource.ServiceCompute)
	if err != nil {
		return zero, err
	}
	vol.State = resource.VolumeInUse
	vol.InstanceID = req.InstanceID
	vol.Device = req.Device
	op.Action = resource.ActionAttachVolume
	op.Targets = []resource.Ref{vol.ID.Ref()}
	return resource.Accepted[resource.Volume]{Operation: op, Items: []resource.Volume{vol}}, nil
}

// etagMismatchError is a stale instance etag. DetachVolume rereads and tries again.
type etagMismatchError struct{}

func (etagMismatchError) Error() string { return "etag mismatch" }

func (c computeClient) DetachVolume(
	ctx context.Context, m backend.Mutation, req resource.DetachVolumeRequest,
) (resource.Accepted[resource.VolumeAttachment], error) {
	var zero resource.Accepted[resource.VolumeAttachment]
	projectID := project(m.Account)
	vol, err := c.getVolume(ctx, projectID, req.VolumeID.String())
	if err != nil {
		return zero, err
	}
	// Two detaches share one instance spec. The etag is the compare-and-swap.
	// A mismatch means the other detach committed, so this attempt rereads.
	for attempt := 0; attempt < 5; attempt++ {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		acc, err := c.detachOnce(ctx, m, projectID, vol, req)
		if !errors.Is(err, etagMismatchError{}) {
			return acc, err
		}
	}
	return zero, resource.Conflict(resource.KindVolume, vol.ID.String(), "instance changed")
}

// detachReplay is a detach this client already committed.
// requestHex is the detach request UUID without dashes.
type detachReplay struct {
	requestHex  string
	device      string
	opLocal     string
	fingerprint string
	instanceID  resource.InstanceID
}

func (c computeClient) detachOnce(
	ctx context.Context, m backend.Mutation, projectID string, vol resource.Volume, req resource.DetachVolumeRequest,
) (resource.Accepted[resource.VolumeAttachment], error) {
	var zero resource.Accepted[resource.VolumeAttachment]
	got, model, bind, bound, err := c.detachBind(ctx, projectID, vol, req.InstanceID)
	if err != nil {
		return zero, err
	}
	if bound {
		if !req.InstanceID.IsZero() && req.InstanceID != bind.InstanceID {
			return zero, resource.AttachmentNotFound(vol.ID)
		}
		if req.Device != "" && req.Device != bind.Device {
			return zero, resource.AttachmentNotFound(vol.ID)
		}
		if bind.Boot {
			// instance.proto rejects a spec without exactly one boot entry, stopped or running.
			return zero, resource.Conflict(resource.KindVolume, vol.ID.String(), "volume is the root device")
		}
		return c.writeDetach(ctx, m, vol, got, model, bind, true)
	}
	// The spec does not name the volume. A repeat of the detach that removed it
	// is the stored record. Anything else is not in use, and must not write.
	if !req.InstanceID.IsZero() {
		elsewhere, scanErr := c.volumeBoundElsewhere(ctx, projectID, vol.ID, req.InstanceID)
		if scanErr != nil {
			return zero, scanErr
		}
		if elsewhere {
			return zero, resource.AttachmentNotFound(vol.ID)
		}
	}
	holder, holderModel, rec, ok, err := c.findDetachReplay(ctx, projectID, vol.ID, req.InstanceID, got, model)
	if err != nil {
		return zero, err
	}
	if !ok || rec.requestHex != detachRequestHex(m.Key) {
		return zero, resource.Conflict(resource.KindVolume, vol.ID.String(), "volume is not in use")
	}
	if rec.opLocal != "" && !detachFingerprintMatches(rec.fingerprint, m.Fingerprint) {
		return zero, resource.IdempotencyMismatch()
	}
	if rec.opLocal != "" {
		return c.acceptDetachReplay(ctx, m.Account, vol, holderModel, rec)
	}
	return c.writeDetach(ctx, m, vol, holder, holderModel, backend.VolumeBind{
		InstanceID: rec.instanceID, Device: rec.device,
	}, false)
}

// detachBind finds the instance spec that names the volume.
// status.instance is only a hint. The spec is the attachment.
func (c computeClient) detachBind(
	ctx context.Context, projectID string, vol resource.Volume, want resource.InstanceID,
) (*computev1.Instance, resource.Instance, backend.VolumeBind, bool, error) {
	if !want.IsZero() {
		got, model, err := c.detachInstance(ctx, projectID, want)
		if err != nil {
			if resource.CodeOf(err) != resource.CodeNotFound {
				return nil, resource.Instance{}, backend.VolumeBind{}, false, err
			}
			onSpec, scanErr := c.volumeBoundElsewhere(ctx, projectID, vol.ID, want)
			if scanErr != nil {
				return nil, resource.Instance{}, backend.VolumeBind{}, false, scanErr
			}
			if onSpec || !vol.InstanceID.IsZero() {
				return nil, resource.Instance{}, backend.VolumeBind{}, false, resource.AttachmentNotFound(vol.ID)
			}
			return nil, resource.Instance{}, backend.VolumeBind{}, false, resource.Conflict(
				resource.KindVolume, vol.ID.String(), "volume is not in use")
		}
		if bind, ok := backend.BindOf(model, vol.ID); ok {
			return got, model, bind, true, nil
		}
		return got, model, backend.VolumeBind{}, false, nil
	}
	var (
		candidate      *computev1.Instance
		candidateModel resource.Instance
		haveCandidate  bool
	)
	if !vol.InstanceID.IsZero() {
		got, model, err := c.detachInstance(ctx, projectID, vol.InstanceID)
		if err != nil && resource.CodeOf(err) != resource.CodeNotFound {
			return nil, resource.Instance{}, backend.VolumeBind{}, false, err
		}
		if err == nil {
			if bind, ok := backend.BindOf(model, vol.ID); ok {
				return got, model, bind, true, nil
			}
			candidate, candidateModel, haveCandidate = got, model, true
		}
	}
	got, model, bind, ok, err := c.findVolumeBind(ctx, projectID, vol.ID)
	if err != nil || ok {
		return got, model, bind, ok, err
	}
	if haveCandidate {
		return candidate, candidateModel, backend.VolumeBind{}, false, nil
	}
	return nil, resource.Instance{}, backend.VolumeBind{}, false, nil
}

func (c computeClient) detachInstance(
	ctx context.Context, projectID string, id resource.InstanceID,
) (*computev1.Instance, resource.Instance, error) {
	name := instanceName(projectID, id.String())
	got, err := c.instances.GetInstance(ctx, &computev1.GetInstanceRequest{Name: name})
	if err != nil {
		return nil, resource.Instance{}, fromNamedRPC(name, err)
	}
	model, err := instanceModel(got)
	if err != nil {
		return nil, resource.Instance{}, err
	}
	return got, model, nil
}

// findVolumeBind pages the caller's instances until one spec names id.
// A repeated page token is an error. Stopping early would hide a later bind.
func (c computeClient) findVolumeBind(
	ctx context.Context, projectID string, id resource.VolumeID,
) (*computev1.Instance, resource.Instance, backend.VolumeBind, bool, error) {
	token := ""
	seen := map[string]struct{}{}
	for {
		if token != "" {
			if _, ok := seen[token]; ok {
				return nil, resource.Instance{}, backend.VolumeBind{}, false, resource.Internal(
					errors.New("instance page token repeated"))
			}
			seen[token] = struct{}{}
		}
		out, err := c.instances.ListInstances(ctx, &computev1.ListInstancesRequest{
			Parent: instanceParent(projectID), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return nil, resource.Instance{}, backend.VolumeBind{}, false, fromRPC(err)
		}
		for _, item := range out.GetInstances() {
			model, err := instanceModel(item)
			if err != nil {
				return nil, resource.Instance{}, backend.VolumeBind{}, false, err
			}
			if bind, ok := backend.BindOf(model, id); ok {
				return item, model, bind, true, nil
			}
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return nil, resource.Instance{}, backend.VolumeBind{}, false, nil
}

// volumeBoundElsewhere reports whether a spec other than skip names id.
func (c computeClient) volumeBoundElsewhere(
	ctx context.Context, projectID string, id resource.VolumeID, skip resource.InstanceID,
) (bool, error) {
	_, model, _, ok, err := c.findVolumeBind(ctx, projectID, id)
	if err != nil || !ok {
		return false, err
	}
	return model.ID != skip, nil
}

// findDetachReplay reads the detach record for id.
// A named instance is the only place a named request may replay.
// A volume-only request pages until some instance still carries the record.
func (c computeClient) findDetachReplay(
	ctx context.Context, projectID string, id resource.VolumeID, want resource.InstanceID,
	hint *computev1.Instance, hintModel resource.Instance,
) (*computev1.Instance, resource.Instance, detachReplay, bool, error) {
	if hint != nil {
		if rec, ok := detachReplayFrom(hint.GetLabels(), id.String()); ok {
			rec.instanceID = hintModel.ID
			return hint, hintModel, rec, true, nil
		}
		if !want.IsZero() {
			return nil, resource.Instance{}, detachReplay{}, false, nil
		}
	}
	token := ""
	seen := map[string]struct{}{}
	for {
		if token != "" {
			if _, ok := seen[token]; ok {
				return nil, resource.Instance{}, detachReplay{}, false, resource.Internal(
					errors.New("instance page token repeated"))
			}
			seen[token] = struct{}{}
		}
		out, err := c.instances.ListInstances(ctx, &computev1.ListInstancesRequest{
			Parent: instanceParent(projectID), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return nil, resource.Instance{}, detachReplay{}, false, fromRPC(err)
		}
		for _, item := range out.GetInstances() {
			rec, ok := detachReplayFrom(item.GetLabels(), id.String())
			if !ok {
				continue
			}
			model, err := instanceModel(item)
			if err != nil {
				return nil, resource.Instance{}, detachReplay{}, false, err
			}
			rec.instanceID = model.ID
			return item, model, rec, true, nil
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return nil, resource.Instance{}, detachReplay{}, false, nil
}

func (c computeClient) writeDetach(
	ctx context.Context, m backend.Mutation, vol resource.Volume,
	got *computev1.Instance, model resource.Instance, bind backend.VolumeBind, drop bool,
) (resource.Accepted[resource.VolumeAttachment], error) {
	var zero resource.Accepted[resource.VolumeAttachment]
	volumes := make([]*computev1.VolumeAttachment, 0, len(got.GetSpec().GetVolumes()))
	for _, v := range got.GetSpec().GetVolumes() {
		if drop && lastSegment(v.GetVolume()) == vol.ID.String() && !v.GetBoot() && v.GetDeviceName() != "boot" {
			continue
		}
		volumes = append(volumes, v)
	}
	if protoBootCount(volumes) != 1 {
		return zero, resource.Conflict(resource.KindVolume, vol.ID.String(), "volume is the root device")
	}
	device := bind.Device
	if device == "" {
		device = vol.Device
	}
	labels, err := instanceUpdateLabels(
		model, got.GetLabels(), resource.ActionDetachVolume, m.Fingerprint,
		detachReplayLabel(vol.ID.String(), detachRequestHex(m.Key), device),
	)
	if err != nil {
		return zero, err
	}
	updated, callErr := c.instances.UpdateInstance(ctx, &computev1.UpdateInstanceRequest{
		RequestId:  requestUUID(m.Key, "detach"),
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.volumes", "labels"}},
		Instance: &computev1.Instance{
			Name:   got.GetName(),
			Etag:   got.GetEtag(),
			Labels: labels,
			Spec:   &computev1.InstanceSpec{Volumes: volumes},
		},
	})
	if etagMismatch(callErr) {
		return zero, etagMismatchError{}
	}
	if err := rpcErr(updated, callErr); err != nil {
		// An empty spec diff has no volume id for the loopback to pass on.
		// The volume was read above, so a not-found from that replay attempt
		// is the not-in-use conflict.
		if !drop && resource.CodeOf(err) == resource.CodeNotFound {
			return zero, resource.Conflict(resource.KindVolume, vol.ID.String(), "volume is not in use")
		}
		return zero, err
	}
	op, err := operationFrom(updated, resource.ServiceCompute)
	if err != nil {
		return zero, err
	}
	// A no-op update still stores a request id. A fresh token must not get that far.
	// A replay of the original request leaves the etag alone.
	if !drop && updated.GetDone() {
		after, err := c.instances.GetInstance(ctx, &computev1.GetInstanceRequest{Name: got.GetName()})
		if err != nil {
			return zero, fromNamedRPC(got.GetName(), err)
		}
		if after.GetEtag() != got.GetEtag() {
			return zero, resource.Conflict(resource.KindVolume, vol.ID.String(), "volume is not in use")
		}
	}
	if err := c.persistDetachOp(ctx, m, got.GetName(), vol.ID.String(), op.ID.Local()); err != nil {
		return zero, err
	}
	op.Action = resource.ActionDetachVolume
	op.Targets = []resource.Ref{bind.InstanceID.Ref()}
	return resource.Accepted[resource.VolumeAttachment]{
		Operation: op,
		Items: []resource.VolumeAttachment{{
			VolumeID: vol.ID, OwnerID: vol.OwnerID, InstanceID: bind.InstanceID, Device: device,
			Status: resource.AttachmentDetaching, AttachTime: detachAttachTime(vol, model),
		}},
	}, nil
}

// persistDetachOp writes the operation id next to the detach record.
// The id is known only after UpdateInstance returns, and a later retry has to
// read it without rebuilding the volume list that request fingerprinted.
func (c computeClient) persistDetachOp(ctx context.Context, m backend.Mutation, name, volID, opLocal string) error {
	key := labelDetachOpPrefix + volID
	value := opLocal + " " + detachFPToken(m.Fingerprint)
	for attempt := 0; attempt < 5; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		got, err := c.instances.GetInstance(ctx, &computev1.GetInstanceRequest{Name: name})
		if err != nil {
			return fromNamedRPC(name, err)
		}
		if got.GetLabels()[key] == value {
			return nil
		}
		labels := maps.Clone(got.GetLabels())
		if labels == nil {
			labels = map[string]string{}
		}
		labels[key] = value
		updated, callErr := c.instances.UpdateInstance(ctx, &computev1.UpdateInstanceRequest{
			RequestId:  requestUUID(m.Key, "detach-op", opLocal, got.GetEtag()),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.volumes", "labels"}},
			Instance: &computev1.Instance{
				Name:   name,
				Etag:   got.GetEtag(),
				Labels: labels,
				Spec:   &computev1.InstanceSpec{Volumes: got.GetSpec().GetVolumes()},
			},
		})
		if etagMismatch(callErr) {
			continue
		}
		if err := rpcErr(updated, callErr); err != nil {
			return err
		}
		return nil
	}
	return resource.Conflict(resource.KindVolume, volID, "instance changed")
}

func (c computeClient) acceptDetachReplay(
	ctx context.Context, account resource.AccountID, vol resource.Volume, inst resource.Instance, rec detachReplay,
) (resource.Accepted[resource.VolumeAttachment], error) {
	var zero resource.Accepted[resource.VolumeAttachment]
	id, err := resource.NewOperationID(resource.ServiceCompute, rec.opLocal)
	if err != nil {
		return zero, resource.Internal(err)
	}
	op := resource.Operation{
		ID: id, Action: resource.ActionDetachVolume, State: resource.OperationRunning,
		OwnerID: vol.OwnerID, Targets: []resource.Ref{rec.instanceID.Ref()},
	}
	if c.computeOps != nil {
		loaded, err := c.GetOperation(ctx, backend.Scope{Account: account}, id)
		if err != nil {
			return zero, err
		}
		op = loaded
		op.Action = resource.ActionDetachVolume
		if len(op.Targets) == 0 {
			op.Targets = []resource.Ref{rec.instanceID.Ref()}
		}
	}
	return resource.Accepted[resource.VolumeAttachment]{
		Operation: op,
		Items: []resource.VolumeAttachment{{
			VolumeID: vol.ID, OwnerID: vol.OwnerID, InstanceID: rec.instanceID, Device: rec.device,
			Status: resource.AttachmentDetaching, AttachTime: detachAttachTime(vol, inst),
		}},
	}, nil
}

// detachAttachTime is the attachment's start.
// The fake records Volume.AttachTime at the attach call. The instance and
// volume protos have no attach timestamp, so this path uses the instance
// launch time, which does not move when the detach itself updates the row.
func detachAttachTime(vol resource.Volume, inst resource.Instance) time.Time {
	if !vol.AttachTime.IsZero() {
		return vol.AttachTime
	}
	return inst.LaunchTime
}

// instanceUpdateLabels replaces an instance label map without dropping the
// image, reservation, or launch labels instanceModel and RunInstances stored.
func instanceUpdateLabels(
	inst resource.Instance, raw map[string]string, action resource.Action, fingerprint string, record map[string]string,
) (map[string]string, error) {
	extra := map[string]string{
		labelAction:      action.String(),
		labelFingerprint: clip(fingerprint, 63),
		labelImage:       inst.ImageID.String(),
		labelReservation: inst.ReservationID.String(),
	}
	if launch := raw[labelLaunch]; launch != "" {
		extra[labelLaunch] = launch
	}
	for key, value := range raw {
		if detachRecordKey(key) {
			extra[key] = value
		}
	}
	maps.Copy(extra, record)
	return withInternalLabels(inst.Tags, extra)
}

func detachReplayLabel(volID, requestHex, device string) map[string]string {
	return map[string]string{labelDetachPrefix + volID: requestHex + " " + device}
}

func detachRequestHex(key string) string {
	return strings.ReplaceAll(requestUUID(key, "detach"), "-", "")
}

func detachFPToken(fingerprint string) string {
	sum := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(sum[:8])
}

func detachFingerprintMatches(token, fingerprint string) bool {
	return token == detachFPToken(fingerprint)
}

func detachRecordKey(key string) bool {
	return strings.HasPrefix(key, labelDetachPrefix) || strings.HasPrefix(key, labelDetachOpPrefix)
}

func detachReplayFrom(labels map[string]string, volID string) (detachReplay, bool) {
	raw, ok := labels[labelDetachPrefix+volID]
	if !ok {
		return detachReplay{}, false
	}
	requestHex, device, ok := strings.Cut(raw, " ")
	if !ok || requestHex == "" {
		return detachReplay{}, false
	}
	rec := detachReplay{requestHex: requestHex, device: device}
	if opLocal, fp, cut := strings.Cut(labels[labelDetachOpPrefix+volID], " "); cut && opLocal != "" {
		rec.opLocal = opLocal
		rec.fingerprint = fp
	}
	return rec, true
}

func protoBootCount(vols []*computev1.VolumeAttachment) int {
	n := 0
	for _, v := range vols {
		if v.GetBoot() || v.GetDeviceName() == "boot" {
			n++
		}
	}
	return n
}

func (c computeClient) DeleteVolume(ctx context.Context, m backend.Mutation, req resource.DeleteVolumeRequest) (resource.Accepted[resource.Volume], error) {
	projectID := project(m.Account)
	vol, err := c.getVolume(ctx, projectID, req.ID.String())
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	deleted, err := c.volumes.DeleteVolume(ctx, &storagev1.DeleteVolumeRequest{
		Name:      volumeName(projectID, req.ID.String()),
		RequestId: requestUUID(m.Key, "delete-vol"),
	})
	if err := rpcErr(deleted, err); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	op, err := operationFrom(deleted, resource.ServiceCompute)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	vol.State = resource.VolumeDeleting
	op.Action = resource.ActionDeleteVolume
	op.Targets = []resource.Ref{vol.ID.Ref()}
	return resource.Accepted[resource.Volume]{Operation: op, Items: []resource.Volume{vol}}, nil
}

// ModifyVolume grows a volume with UpdateVolume on spec.size_gib, the only
// volume update vws-storage serves.
func (c computeClient) ModifyVolume(ctx context.Context, m backend.Mutation, req resource.ModifyVolumeRequest) (resource.Accepted[resource.Volume], error) {
	projectID := project(m.Account)
	vol, err := c.getVolume(ctx, projectID, req.ID.String())
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	if req.SizeGiB < vol.SizeGiB {
		return resource.Accepted[resource.Volume]{}, resource.Invalid("size", "a volume cannot shrink")
	}
	updated, err := c.volumes.UpdateVolume(ctx, &storagev1.UpdateVolumeRequest{
		Volume: &storagev1.Volume{
			Name: volumeName(projectID, req.ID.String()),
			Spec: &storagev1.VolumeSpec{SizeGib: req.SizeGiB, Type: storageType(vol.Type)},
		},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.size_gib"}},
		RequestId:  requestUUID(m.Key, "modify-vol"),
	})
	if err := rpcErr(updated, err); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	op, err := operationFrom(updated, resource.ServiceCompute)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	vol.SizeGiB = req.SizeGiB
	op.Action = resource.ActionModifyVolume
	op.Targets = []resource.Ref{vol.ID.Ref()}
	return resource.Accepted[resource.Volume]{Operation: op, Items: []resource.Volume{vol}}, nil
}

func (c computeClient) DescribeVolumes(ctx context.Context, s backend.Scope, q resource.VolumeQuery) (resource.Page[resource.Volume], error) {
	projectID := project(s.Account)
	if len(q.IDs) > 0 {
		items := make([]resource.Volume, 0, len(q.IDs))
		for _, id := range q.IDs {
			vol, err := c.getVolume(ctx, projectID, id.String())
			if resource.CodeOf(err) == resource.CodeNotFound {
				if len(q.IDs) == 1 {
					return resource.Page[resource.Volume]{}, err
				}
				continue
			}
			if err != nil {
				return resource.Page[resource.Volume]{}, err
			}
			items = append(items, vol)
		}
		return pageByID(items, q.Page, func(item resource.Volume) string { return item.ID.String() })
	}
	out, err := c.volumes.ListVolumes(ctx, &storagev1.ListVolumesRequest{
		Parent: volumeParent(projectID), PageSize: pageSize(q.Page.Size), PageToken: q.Page.Token,
	})
	if err != nil {
		return resource.Page[resource.Volume]{}, fromRPC(err)
	}
	items := make([]resource.Volume, 0, len(out.GetVolumes()))
	for _, item := range out.GetVolumes() {
		vol, err := volumeModel(item)
		if err != nil {
			return resource.Page[resource.Volume]{}, err
		}
		items = append(items, vol)
	}
	return resource.Page[resource.Volume]{Items: items, NextToken: out.GetNextPageToken()}, nil
}

func (c computeClient) DescribeImages(ctx context.Context, s backend.Scope, q resource.ImageQuery) (resource.Page[resource.Image], error) {
	if err := ctx.Err(); err != nil {
		return resource.Page[resource.Image]{}, err
	}
	want := map[string]struct{}{}
	for _, id := range q.IDs {
		want[id.String()] = struct{}{}
	}
	var items []resource.Image
	for _, img := range resource.KnownImages(s.Account) {
		if len(want) > 0 {
			if _, ok := want[img.ID.String()]; !ok {
				continue
			}
		}
		items = append(items, img)
	}
	if len(q.IDs) == 1 && len(items) == 0 {
		return resource.Page[resource.Image]{}, resource.NotFound(resource.KindImage, q.IDs[0].String())
	}
	return pageByID(items, q.Page, func(item resource.Image) string { return item.ID.String() })
}

func (c computeClient) CreateKeyPair(ctx context.Context, m backend.Mutation, req resource.CreateKeyPairRequest) (resource.Accepted[resource.KeyPair], error) {
	var pair sshkey.Pair
	if req.PublicKey != "" {
		pub, err := sshkey.ParsePublic(req.PublicKey)
		if err != nil {
			return resource.Accepted[resource.KeyPair]{}, resource.Invalid("publicKeyMaterial", err.Error())
		}
		pair = sshkey.Pair{Public: pub.Line, AWSFingerprint: pub.AWSFingerprint}
		req.Type = pub.Type
	} else {
		var err error
		if pair, err = derivedKey(req.Type, m.Key, "key-seed"); err != nil {
			return resource.Accepted[resource.KeyPair]{}, err
		}
	}
	projectID := project(m.Account)
	labels := nameLabels(req.Name)
	labels[labelFingerprint] = clip(m.Fingerprint, 63)
	if req.PublicKey == "" && req.Type == resource.KeyTypeRSA {
		// The private key is never stored, so EC2's fingerprint of it is.
		labels[labelKeySHA1] = strings.ReplaceAll(pair.AWSFingerprint, ":", "")
	}
	material := pair.Private
	if req.Format == resource.KeyFormatPPK {
		material = pair.PPK(req.Name)
	}
	created, err := c.keys.CreateKeyPair(ctx, &computev1.CreateKeyPairRequest{
		Parent:    regionParent(projectID),
		KeyPairId: derivedID("key-", m.Key, "key"),
		RequestId: requestUUID(m.Key, "key"),
		KeyPair: &computev1.KeyPair{
			Labels: labels,
			Spec:   &computev1.KeyPairSpec{PublicKey: pair.Public},
		},
	})
	if err := rpcErr(created, err); err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	op, err := operationFrom(created, resource.ServiceCompute)
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	metaName, err := metadataResource(created)
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	id, err := resource.Parse[resource.KeyPairID](lastSegment(metaName))
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, resource.Internal(err)
	}
	owner, err := accountIn(metaName)
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	key := resource.KeyPair{
		ID: id, OwnerID: owner, Name: req.Name, Fingerprint: pair.AWSFingerprint, Material: material, Type: req.Type,
	}
	op.Action = resource.ActionCreateKeyPair
	op.Targets = []resource.Ref{id.Ref()}
	return resource.Accepted[resource.KeyPair]{Operation: op, Items: []resource.KeyPair{key}}, nil
}

func (c networkClient) CreateVpc(ctx context.Context, m backend.Mutation, req resource.CreateVpcRequest) (resource.Accepted[resource.Vpc], error) {
	projectID := project(m.Account)
	labels, err := withInternalLabels(req.Tags, map[string]string{labelFingerprint: clip(m.Fingerprint, 63)})
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	created, err := c.vpcs.CreateVpc(ctx, &networkv1.CreateVpcRequest{
		Parent:    regionParent(projectID),
		VpcId:     derivedID("vpc-", m.Key, "vpc"),
		RequestId: requestUUID(m.Key, "user-vpc"),
		Vpc: &networkv1.Vpc{
			Labels: labels,
			Spec:   &networkv1.VpcSpec{Ipv4Cidr: req.Cidr},
		},
	})
	if err := rpcErr(created, err); err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	op, err := operationFrom(created, resource.ServiceNetwork)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	metaName, err := metadataResource(created)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	id, err := resource.Parse[resource.VpcID](lastSegment(metaName))
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, resource.Internal(err)
	}
	owner, err := accountIn(metaName)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	vpc := resource.Vpc{ID: id, OwnerID: owner, Cidr: req.Cidr, State: resource.VpcPending, Tags: req.Tags}
	op.Action = resource.ActionCreateVpc
	op.Targets = []resource.Ref{id.Ref()}
	return resource.Accepted[resource.Vpc]{Operation: op, Items: []resource.Vpc{vpc}}, nil
}

func (c networkClient) DeleteVpc(ctx context.Context, m backend.Mutation, req resource.DeleteVpcRequest) (resource.Accepted[resource.Vpc], error) {
	projectID := project(m.Account)
	vpc, err := c.getVpc(ctx, projectID, req.ID.String())
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	deleted, err := c.vpcs.DeleteVpc(ctx, &networkv1.DeleteVpcRequest{
		Name:      vpcName(projectID, req.ID.String()),
		RequestId: requestUUID(m.Key, "delete-vpc"),
	})
	if err := rpcErr(deleted, err); err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	op, err := operationFrom(deleted, resource.ServiceNetwork)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	vpc.State = resource.VpcDeleting
	op.Action = resource.ActionDeleteVpc
	op.Targets = []resource.Ref{vpc.ID.Ref()}
	return resource.Accepted[resource.Vpc]{Operation: op, Items: []resource.Vpc{vpc}}, nil
}

func (c networkClient) DescribeVpcs(ctx context.Context, s backend.Scope, q resource.VpcQuery) (resource.Page[resource.Vpc], error) {
	projectID := project(s.Account)
	if len(q.IDs) == 1 {
		vpc, err := c.getVpc(ctx, projectID, q.IDs[0].String())
		if err != nil {
			return resource.Page[resource.Vpc]{}, err
		}
		return pageByID([]resource.Vpc{vpc}, q.Page, func(item resource.Vpc) string { return item.ID.String() })
	}
	want := map[string]struct{}{}
	for _, id := range q.IDs {
		want[id.String()] = struct{}{}
	}
	var items []resource.Vpc
	token := ""
	for page := 0; page < 50; page++ {
		out, err := c.vpcs.ListVpcs(ctx, &networkv1.ListVpcsRequest{
			Parent: regionParent(projectID), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return resource.Page[resource.Vpc]{}, fromRPC(err)
		}
		for _, item := range out.GetVpcs() {
			idText := lastSegment(item.GetName())
			if _, err := resource.Parse[resource.VpcID](idText); err != nil {
				continue
			}
			if len(want) > 0 {
				if _, ok := want[idText]; !ok {
					continue
				}
			}
			vpc, err := c.getVpc(ctx, projectID, idText)
			if resource.CodeOf(err) == resource.CodeNotFound {
				continue
			}
			if err != nil {
				return resource.Page[resource.Vpc]{}, err
			}
			items = append(items, vpc)
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	if len(q.IDs) == 1 && len(items) == 0 {
		return resource.Page[resource.Vpc]{}, resource.NotFound(resource.KindVpc, q.IDs[0].String())
	}
	return pageByID(items, q.Page, func(item resource.Vpc) string { return item.ID.String() })
}

func (c networkClient) CreateSecurityGroup(ctx context.Context, m backend.Mutation, req resource.CreateSecurityGroupRequest) (resource.Accepted[resource.SecurityGroup], error) {
	projectID := project(m.Account)
	created, err := c.groups.CreateSecurityGroup(ctx, &networkv1.CreateSecurityGroupRequest{
		Parent:          vpcName(projectID, req.VpcID.String()),
		SecurityGroupId: derivedID("sg-", m.Key, "sg"),
		RequestId:       requestUUID(m.Key, "sg"),
		SecurityGroup: &networkv1.SecurityGroup{
			Labels: map[string]string{labelFingerprint: clip(m.Fingerprint, 63)},
			Spec:   &networkv1.SecurityGroupSpec{Description: req.Name},
		},
	})
	if err := rpcErr(created, err); err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	op, err := operationFrom(created, resource.ServiceNetwork)
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	metaName, err := metadataResource(created)
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	id, err := resource.Parse[resource.SecurityGroupID](lastSegment(metaName))
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, resource.Internal(err)
	}
	owner, err := accountIn(metaName)
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	group := resource.SecurityGroup{ID: id, OwnerID: owner, Name: req.Name, VpcID: req.VpcID}
	op.Action = resource.ActionCreateSecurityGroup
	op.Targets = []resource.Ref{id.Ref()}
	return resource.Accepted[resource.SecurityGroup]{Operation: op, Items: []resource.SecurityGroup{group}}, nil
}

func (c networkClient) AuthorizeSecurityGroupIngress(ctx context.Context, m backend.Mutation, req resource.AuthorizeSecurityGroupIngressRequest) (resource.Accepted[resource.SecurityGroup], error) {
	var zero resource.Accepted[resource.SecurityGroup]
	projectID := project(m.Account)
	rec, found, err := c.findIngressReplay(ctx, projectID, m.Key)
	if err != nil {
		return zero, err
	}
	if found {
		if rec.groupID != req.ID.String() || !detachFingerprintMatches(rec.fp, m.Fingerprint) {
			return zero, resource.IdempotencyMismatch()
		}
		if rec.opLocal != "" {
			return c.acceptIngressReplay(ctx, m, rec)
		}
		// The rules and the fingerprint label are already stored. The duplicate
		// check would report that first call as AlreadyExists.
		current, err := groupModel(rec.msg)
		if err != nil {
			return zero, err
		}
		return c.writeIngress(ctx, m, rec.msg, current, current.Rules)
	}
	msg, err := c.findGroupMessage(ctx, projectID, req.ID.String())
	if err != nil {
		if resource.CodeOf(err) == resource.CodeNotFound {
			return zero, resource.GroupNotFound(req.ID.String())
		}
		return zero, err
	}
	current, err := groupModel(msg)
	if err != nil {
		return zero, err
	}
	if err := resource.CheckIngressBatch(current.ID.String(), current.Rules, req.Rules); err != nil {
		return zero, err
	}
	rules := append([]resource.IngressRule{}, current.Rules...)
	for _, rule := range req.Rules {
		rules = append(rules, rule.IngressRule)
	}
	return c.writeIngress(ctx, m, msg, current, rules)
}

type ingressReplay struct {
	groupID string
	fp      string
	opLocal string
	msg     *networkv1.SecurityGroup
}

func (c networkClient) writeIngress(
	ctx context.Context, m backend.Mutation, msg *networkv1.SecurityGroup,
	current resource.SecurityGroup, rules []resource.IngressRule,
) (resource.Accepted[resource.SecurityGroup], error) {
	var zero resource.Accepted[resource.SecurityGroup]
	protoRules := make([]*networkv1.SecurityGroupRule, 0, len(rules))
	for i, rule := range rules {
		protoRule, err := ruleProto(rule, derivedID("r", m.Key, "rule", strconv.Itoa(i)))
		if err != nil {
			return zero, err
		}
		protoRules = append(protoRules, protoRule)
	}
	labels := maps.Clone(msg.GetLabels())
	if labels == nil {
		labels = map[string]string{}
	}
	labels[ingressTokenLabel(m.Key)] = detachFPToken(m.Fingerprint) + " " + current.ID.String()
	updated, err := c.groups.UpdateSecurityGroup(ctx, &networkv1.UpdateSecurityGroupRequest{
		RequestId:  requestUUID(m.Key, "ingress"),
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.rules", "labels"}},
		SecurityGroup: &networkv1.SecurityGroup{
			Name:   msg.GetName(),
			Labels: labels,
			Spec:   &networkv1.SecurityGroupSpec{Rules: protoRules},
		},
	})
	if err := rpcErr(updated, err); err != nil {
		return zero, err
	}
	op, err := operationFrom(updated, resource.ServiceNetwork)
	if err != nil {
		return zero, err
	}
	if err := c.persistIngressOp(ctx, m, msg.GetName(), op.ID.Local()); err != nil {
		return zero, err
	}
	got, err := c.findGroup(ctx, project(m.Account), current.ID.String())
	if err != nil {
		return zero, err
	}
	op.Action = resource.ActionAuthorizeSecurityGroupIngress
	op.Targets = []resource.Ref{got.ID.Ref()}
	return resource.Accepted[resource.SecurityGroup]{Operation: op, Items: []resource.SecurityGroup{got}}, nil
}

func (c networkClient) persistIngressOp(ctx context.Context, m backend.Mutation, name, opLocal string) error {
	key := ingressOpLabel(m.Key)
	got, err := c.groups.GetSecurityGroup(ctx, &networkv1.GetSecurityGroupRequest{Name: name})
	if err != nil {
		return fromNamedRPC(name, err)
	}
	if got.GetLabels()[key] == opLocal {
		return nil
	}
	labels := maps.Clone(got.GetLabels())
	if labels == nil {
		labels = map[string]string{}
	}
	labels[key] = opLocal
	updated, callErr := c.groups.UpdateSecurityGroup(ctx, &networkv1.UpdateSecurityGroupRequest{
		RequestId:  requestUUID(m.Key, "ingress-op"),
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.rules", "labels"}},
		SecurityGroup: &networkv1.SecurityGroup{
			Name:   name,
			Labels: labels,
			Spec:   &networkv1.SecurityGroupSpec{Rules: got.GetSpec().GetRules()},
		},
	})
	return rpcErr(updated, callErr)
}

func (c networkClient) acceptIngressReplay(
	ctx context.Context, m backend.Mutation, rec ingressReplay,
) (resource.Accepted[resource.SecurityGroup], error) {
	var zero resource.Accepted[resource.SecurityGroup]
	id, err := resource.NewOperationID(resource.ServiceNetwork, rec.opLocal)
	if err != nil {
		return zero, resource.Internal(err)
	}
	op, err := c.GetOperation(ctx, backend.Scope{Account: m.Account}, id)
	if err != nil {
		return zero, err
	}
	got, err := groupModel(rec.msg)
	if err != nil {
		return zero, err
	}
	op.Action = resource.ActionAuthorizeSecurityGroupIngress
	op.Targets = []resource.Ref{got.ID.Ref()}
	return resource.Accepted[resource.SecurityGroup]{Operation: op, Items: []resource.SecurityGroup{got}}, nil
}

func (c networkClient) findIngressReplay(ctx context.Context, projectID, key string) (ingressReplay, bool, error) {
	var zero ingressReplay
	tokenKey := ingressTokenLabel(key)
	opKey := ingressOpLabel(key)
	page := ""
	for vpcPage := 0; vpcPage < 50; vpcPage++ {
		out, err := c.vpcs.ListVpcs(ctx, &networkv1.ListVpcsRequest{
			Parent: regionParent(projectID), PageSize: 100, PageToken: page,
		})
		if err != nil {
			return zero, false, fromRPC(err)
		}
		for _, vpc := range out.GetVpcs() {
			groupToken := ""
			for groupPage := 0; groupPage < 50; groupPage++ {
				listed, err := c.groups.ListSecurityGroups(ctx, &networkv1.ListSecurityGroupsRequest{
					Parent: vpc.GetName(), PageSize: 100, PageToken: groupToken,
				})
				if err != nil {
					return zero, false, fromRPC(err)
				}
				for _, item := range listed.GetSecurityGroups() {
					raw, ok := item.GetLabels()[tokenKey]
					if !ok {
						continue
					}
					fp, groupID, cut := strings.Cut(raw, " ")
					if !cut || fp == "" || groupID == "" {
						return zero, false, resource.Internal(errors.New("bad ingress replay label"))
					}
					return ingressReplay{
						groupID: groupID, fp: fp, opLocal: item.GetLabels()[opKey], msg: item,
					}, true, nil
				}
				groupToken = listed.GetNextPageToken()
				if groupToken == "" {
					break
				}
			}
		}
		page = out.GetNextPageToken()
		if page == "" {
			break
		}
	}
	return zero, false, nil
}

func ingressTokenLabel(key string) string { return labelIngressPrefix + ingressLabelHex(key) }

func ingressOpLabel(key string) string { return labelIngressOpPrefix + ingressLabelHex(key) }

func ingressLabelHex(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

func (c computeClient) getVolume(ctx context.Context, projectID, id string) (resource.Volume, error) {
	name := volumeName(projectID, id)
	out, err := c.volumes.GetVolume(ctx, &storagev1.GetVolumeRequest{Name: name})
	if err != nil {
		return resource.Volume{}, fromNamedRPC(name, err)
	}
	return volumeModel(out)
}

func (c networkClient) getVpc(ctx context.Context, projectID, id string) (resource.Vpc, error) {
	name := vpcName(projectID, id)
	out, err := c.vpcs.GetVpc(ctx, &networkv1.GetVpcRequest{Name: name})
	if err != nil {
		return resource.Vpc{}, fromNamedRPC(name, err)
	}
	return vpcModel(out)
}

func (c networkClient) findGroup(ctx context.Context, projectID, id string) (resource.SecurityGroup, error) {
	msg, err := c.findGroupMessage(ctx, projectID, id)
	if err != nil {
		return resource.SecurityGroup{}, err
	}
	return groupModel(msg)
}

func (c networkClient) findGroupMessage(ctx context.Context, projectID, id string) (*networkv1.SecurityGroup, error) {
	token := ""
	for page := 0; page < 20; page++ {
		out, err := c.vpcs.ListVpcs(ctx, &networkv1.ListVpcsRequest{
			Parent: regionParent(projectID), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return nil, fromRPC(err)
		}
		for _, vpc := range out.GetVpcs() {
			got, err := c.groups.GetSecurityGroup(ctx, &networkv1.GetSecurityGroupRequest{
				Name: vpc.GetName() + "/securityGroups/" + id,
			})
			if err != nil {
				if resource.CodeOf(fromRPC(err)) == resource.CodeNotFound {
					continue
				}
				return nil, fromRPC(err)
			}
			return got, nil
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return nil, resource.NotFound(resource.KindSecurityGroup, id)
}

func acceptedVolume(op *longrunningpb.Operation, req resource.CreateVolumeRequest, state resource.VolumeState) (resource.Accepted[resource.Volume], error) {
	parsed, err := operationFrom(op, resource.ServiceCompute)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	metaName, err := metadataResource(op)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	id, err := resource.Parse[resource.VolumeID](lastSegment(metaName))
	if err != nil {
		return resource.Accepted[resource.Volume]{}, resource.Internal(err)
	}
	named, err := accountIn(metaName)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	vol := resource.Volume{ID: id, OwnerID: named, SizeGiB: req.SizeGiB, Zone: req.Zone, Type: req.Type, State: state, SnapshotID: req.SnapshotID, CreateTime: parsed.CreateTime}
	parsed.Action = resource.ActionCreateVolume
	parsed.Targets = []resource.Ref{id.Ref()}
	return resource.Accepted[resource.Volume]{Operation: parsed, Items: []resource.Volume{vol}}, nil
}

func nameLabels(name string) map[string]string {
	keys := []string{"keyname", "keyname2", "keyname3", "keyname4", "keyname5"}
	out := map[string]string{}
	for i, key := range keys {
		start := i * 63
		if start >= len(name) {
			break
		}
		end := start + 63
		if end > len(name) {
			end = len(name)
		}
		out[key] = name[start:end]
	}
	return out
}

func stateRefs(items []resource.InstanceStateChange) []resource.Ref {
	out := make([]resource.Ref, 0, len(items))
	for _, item := range items {
		out = append(out, item.ID.Ref())
	}
	return out
}

func volumeModel(in *storagev1.Volume) (resource.Volume, error) {
	if in == nil {
		return resource.Volume{}, resource.Internal(errors.New("missing volume"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 6 || parts[4] != "volumes" {
		return resource.Volume{}, resource.Internal(errors.New("bad volume name"))
	}
	id, err := resource.Parse[resource.VolumeID](parts[5])
	if err != nil {
		return resource.Volume{}, resource.Internal(err)
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.Volume{}, err
	}
	state, err := volumeStateOf(in)
	if err != nil {
		return resource.Volume{}, err
	}
	var inst resource.InstanceID
	if name := in.GetStatus().GetInstance(); name != "" {
		parsed, err := resource.Parse[resource.InstanceID](lastSegment(name))
		if err != nil {
			return resource.Volume{}, resource.Internal(err)
		}
		inst = parsed
	}
	var snap resource.SnapshotID
	if name := in.GetSpec().GetSnapshot(); name != "" {
		parsed, err := resource.Parse[resource.SnapshotID](lastSegment(name))
		if err != nil {
			return resource.Volume{}, resource.Internal(err)
		}
		snap = parsed
	}
	vol := resource.Volume{
		ID: id, OwnerID: owner, SizeGiB: in.GetSpec().GetSizeGib(), Zone: parts[3], SnapshotID: snap,
		Type: volumeTypeOf(in.GetSpec().GetType()), State: state, InstanceID: inst, Device: in.GetStatus().GetDeviceName(),
		CreateTime: in.GetCreateTime().AsTime().UTC(),
	}
	if rootVolume(in) {
		// RunInstances made it from the image, and compute deletes it with
		// the instance. Storage may not report the attachment, so the
		// instance comes from the label RunInstances wrote.
		vol.DeleteOnTermination = true
		if vol.InstanceID.IsZero() {
			if parsed, err := resource.Parse[resource.InstanceID](in.GetLabels()[labelInstance]); err == nil {
				vol.InstanceID = parsed
			}
		}
		if !vol.InstanceID.IsZero() {
			vol.Device = resource.RootDeviceName
			if vol.State == resource.VolumeAvailable {
				vol.State = resource.VolumeInUse
			}
		}
	}
	return vol, nil
}

func volumeStateOf(in *storagev1.Volume) (resource.VolumeState, error) {
	obs := in.GetStatus().GetObserved().GetState()
	// An attachment is in-use, except a failed volume, which EC2 reports as error.
	if in.GetStatus().GetInstance() != "" && obs != commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR {
		return resource.VolumeInUse, nil
	}
	switch obs {
	case commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING, commonv1.ReconciliationState_RECONCILIATION_STATE_RECONCILING:
		return resource.VolumeCreating, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_READY:
		return resource.VolumeAvailable, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING:
		return resource.VolumeDeleting, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR:
		return resource.VolumeError, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED:
		return "", resource.Internal(errors.New("bad volume state"))
	default:
		return "", resource.Internal(errors.New("bad volume state"))
	}
}

func volumeProto(v resource.Volume, projectID string) *storagev1.Volume {
	obs := commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING
	switch v.State {
	case resource.VolumeAvailable, resource.VolumeInUse:
		obs = commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	case resource.VolumeDeleting:
		obs = commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING
	case resource.VolumeCreating:
		obs = commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING
	case resource.VolumeError:
		obs = commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR
	}
	status := &storagev1.VolumeStatus{
		Observed:   &commonv1.ObservedState{State: obs},
		DeviceName: v.Device,
	}
	if !v.InstanceID.IsZero() {
		status.Instance = instanceName(projectID, v.InstanceID.String())
	}
	var created *timestamppb.Timestamp
	if !v.CreateTime.IsZero() {
		created = timestamppb.New(v.CreateTime)
	}
	spec := &storagev1.VolumeSpec{SizeGib: v.SizeGiB, Type: storagev1.VolumeType_VOLUME_TYPE_SSD}
	if !v.SnapshotID.IsZero() {
		spec.Source = &storagev1.VolumeSpec_Snapshot{Snapshot: snapshotName(projectID, v.SnapshotID.String())}
	}
	if v.DeleteOnTermination {
		spec.Source = &storagev1.VolumeSpec_Image{Image: imageName(projectID, "ami-0123456789abcdef0")}
	}
	return &storagev1.Volume{
		CreateTime: created,
		Name:       volumeName(projectID, v.ID.String()),
		Spec:       spec,
		Status:     status,
	}
}

func vpcModel(in *networkv1.Vpc) (resource.Vpc, error) {
	if in == nil {
		return resource.Vpc{}, resource.Internal(errors.New("missing vpc"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 6 || parts[4] != "vpcs" {
		return resource.Vpc{}, resource.Internal(errors.New("bad vpc name"))
	}
	id, err := resource.Parse[resource.VpcID](parts[5])
	if err != nil {
		return resource.Vpc{}, resource.Internal(err)
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.Vpc{}, err
	}
	state, err := vpcStateOf(in.GetStatus().GetObserved().GetState())
	if err != nil {
		return resource.Vpc{}, err
	}
	return resource.Vpc{ID: id, OwnerID: owner, Cidr: in.GetSpec().GetIpv4Cidr(), State: state, Tags: userTags(in.GetLabels())}, nil
}

func vpcStateOf(obs commonv1.ReconciliationState) (string, error) {
	switch obs {
	case commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING, commonv1.ReconciliationState_RECONCILIATION_STATE_RECONCILING:
		return resource.VpcPending, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_READY:
		return resource.VpcAvailable, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING:
		return resource.VpcDeleting, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR, commonv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED:
		return "", resource.Internal(errors.New("bad vpc state"))
	default:
		return "", resource.Internal(errors.New("bad vpc state"))
	}
}

func vpcProto(v resource.Vpc, projectID string) *networkv1.Vpc {
	// The tags were accepted when they were stored, so they fit.
	labels, _ := withInternalLabels(v.Tags, nil) //nolint:errcheck // accepted tags fit
	return &networkv1.Vpc{
		Name:   vpcName(projectID, v.ID.String()),
		Labels: labels,
		Spec:   &networkv1.VpcSpec{Ipv4Cidr: v.Cidr},
		Status: &networkv1.VpcStatus{Observed: &commonv1.ObservedState{State: vpcObserved(v.State)}},
	}
}

func vpcObserved(state string) commonv1.ReconciliationState {
	switch state {
	case resource.VpcAvailable:
		return commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	case resource.VpcDeleting:
		return commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING
	default:
		return commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING
	}
}

func groupModel(in *networkv1.SecurityGroup) (resource.SecurityGroup, error) {
	if in == nil {
		return resource.SecurityGroup{}, resource.Internal(errors.New("missing security group"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 8 || parts[6] != "securityGroups" {
		return resource.SecurityGroup{}, resource.Internal(errors.New("bad security group name"))
	}
	id, err := resource.Parse[resource.SecurityGroupID](parts[7])
	if err != nil {
		return resource.SecurityGroup{}, resource.Internal(err)
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.SecurityGroup{}, err
	}
	vpcID, err := resource.Parse[resource.VpcID](parts[5])
	if err != nil {
		return resource.SecurityGroup{}, resource.Internal(err)
	}
	var rules []resource.IngressRule
	for _, rule := range in.GetSpec().GetRules() {
		if rule.GetDirection() != networkv1.Direction_DIRECTION_INGRESS {
			continue
		}
		rules = append(rules, resource.IngressRule{
			Protocol: protocolName(rule.GetProtocol()),
			FromPort: int(rule.GetFromPort()),
			ToPort:   int(rule.GetToPort()),
			Cidr:     rule.GetCidr(),
		})
	}
	return resource.SecurityGroup{
		ID: id, OwnerID: owner, Name: in.GetSpec().GetDescription(), VpcID: vpcID, Rules: rules,
	}, nil
}

func protocolOf(name string) (networkv1.Protocol, error) {
	switch name {
	case "tcp":
		return networkv1.Protocol_PROTOCOL_TCP, nil
	case "udp":
		return networkv1.Protocol_PROTOCOL_UDP, nil
	case "icmp":
		return networkv1.Protocol_PROTOCOL_ICMP, nil
	case "-1", "all":
		return networkv1.Protocol_PROTOCOL_ALL, nil
	default:
		return networkv1.Protocol_PROTOCOL_UNSPECIFIED, resource.Invalid("ipProtocol", "unsupported")
	}
}

func ruleProto(rule resource.IngressRule, id string) (*networkv1.SecurityGroupRule, error) {
	protocol, err := protocolOf(rule.Protocol)
	if err != nil {
		return nil, err
	}
	return &networkv1.SecurityGroupRule{
		Id:        id,
		Direction: networkv1.Direction_DIRECTION_INGRESS,
		Protocol:  protocol,
		FromPort:  int32(rule.FromPort),
		ToPort:    int32(rule.ToPort),
		Target:    &networkv1.SecurityGroupRule_Cidr{Cidr: rule.Cidr},
	}, nil
}

// rootVolume reports a boot volume, which RunInstances creates from an image.
func rootVolume(in *storagev1.Volume) bool {
	return in.GetSpec().GetImage() != ""
}

func protocolName(p networkv1.Protocol) string {
	switch p {
	case networkv1.Protocol_PROTOCOL_TCP:
		return "tcp"
	case networkv1.Protocol_PROTOCOL_UDP:
		return "udp"
	case networkv1.Protocol_PROTOCOL_ICMP:
		return "icmp"
	case networkv1.Protocol_PROTOCOL_ALL:
		return "-1"
	case networkv1.Protocol_PROTOCOL_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

// derivedKey's domain is "key-seed". The key id and the request id use a
// different domain, so neither published value is the private key.
// derivedKey makes the key pair a create with this mutation key returns. A
// retry derives the same key, so compute sees the same public key and the
// caller gets back the private key it got the first time.
func derivedKey(typ resource.KeyType, parts ...string) (sshkey.Pair, error) {
	pair, err := sshkey.Generate(typ, &seedStream{seed: hashParts(parts...)})
	if err != nil {
		return sshkey.Pair{}, resource.Internal(err)
	}
	return pair, nil
}

// seedStream is SHA-256 in counter mode over seed.
type seedStream struct {
	seed [32]byte
	n    uint64
	buf  []byte
}

func (s *seedStream) Read(p []byte) (int, error) {
	for len(s.buf) < len(p) {
		var block [40]byte
		copy(block[:], s.seed[:])
		binary.BigEndian.PutUint64(block[32:], s.n)
		s.n++
		sum := sha256.Sum256(block[:])
		s.buf = append(s.buf, sum[:]...)
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

// storageType maps an EC2 volume type to the storage tier. The storage proto
// has only STANDARD and SSD, so gp2 and gp3 both land on SSD.
func storageType(t resource.VolumeType) storagev1.VolumeType {
	if t == resource.VolumeStandard {
		return storagev1.VolumeType_VOLUME_TYPE_STANDARD
	}
	return storagev1.VolumeType_VOLUME_TYPE_SSD
}

// volumeTypeOf reports an SSD volume as gp2 because storage does not keep
// which SSD type was asked for.
func volumeTypeOf(t storagev1.VolumeType) resource.VolumeType {
	if t == storagev1.VolumeType_VOLUME_TYPE_STANDARD {
		return resource.VolumeStandard
	}
	return resource.VolumeGP2
}
