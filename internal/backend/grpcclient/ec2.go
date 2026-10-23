package grpcclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
// Compute replaces the whole label map, so the write keeps the internal
// labels and detach records the instance carries (writeInstanceLabels).
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
		updated, _, err := c.writeInstanceLabels(ctx, projectID, inst.ID, func(
			got *computev1.Instance, model resource.Instance,
		) (*computev1.UpdateInstanceRequest, error) {
			tags, err := resource.MergeTags(model.Tags, req.Tags)
			if err != nil {
				return nil, err
			}
			model.Tags = tags
			labels, err := instanceUpdateLabels(model, got.GetLabels(), resource.ActionCreateTags, m.Fingerprint, nil, c.clock())
			if err != nil {
				return nil, err
			}
			return &computev1.UpdateInstanceRequest{
				RequestId:  requestUUID(m.Key, "tags", hex.EncodeToString([]byte{byte(i)})),
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}},
				Instance:   &computev1.Instance{Name: got.GetName(), Labels: labels},
			}, nil
		})
		if err != nil {
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
		var mid resource.InstanceState
		updated, cur, err := c.writeInstanceLabels(ctx, projectID, inst.ID, func(
			got *computev1.Instance, model resource.Instance,
		) (*computev1.UpdateInstanceRequest, error) {
			next, _, err := resource.NextInstanceState(action, model.State)
			if err != nil {
				return nil, err
			}
			mid = next
			labels, err := instanceUpdateLabels(model, got.GetLabels(), action, m.Fingerprint, nil, c.clock())
			if err != nil {
				return nil, err
			}
			return &computev1.UpdateInstanceRequest{
				RequestId:  requestUUID(m.Key, action.String(), hex.EncodeToString([]byte{byte(i)})),
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.power", "labels"}},
				Instance: &computev1.Instance{
					Name:   got.GetName(),
					Labels: labels,
					Spec: &computev1.InstanceSpec{
						MachineType: model.InstanceType,
						Power:       power,
						NetworkInterfaces: []*computev1.NetworkInterface{{
							DeviceName: "nic0",
							Subnet:     subnetName(projectID, "", model.SubnetID.String()),
						}},
					},
				},
			}, nil
		})
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		inst = cur
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

// writeInstanceLabels sends the update build makes from the current instance
// with that instance's etag. Compute replaces the whole label map, so build
// starts from the labels it was given (instanceUpdateLabels), and the etag
// keeps a detach record written in between from being dropped: a stale etag
// rereads and builds again. The request id does not change, because compute
// stores no request it rejected for its etag.
func (c computeClient) writeInstanceLabels(
	ctx context.Context, projectID string, id resource.InstanceID,
	build func(*computev1.Instance, resource.Instance) (*computev1.UpdateInstanceRequest, error),
) (*longrunningpb.Operation, resource.Instance, error) {
	for attempt := 0; attempt < 5; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, resource.Instance{}, err
		}
		got, model, err := c.detachInstance(ctx, projectID, id)
		if err != nil {
			return nil, resource.Instance{}, err
		}
		req, err := build(got, model)
		if err != nil {
			return nil, resource.Instance{}, err
		}
		req.Instance.Etag = got.GetEtag()
		updated, callErr := c.instances.UpdateInstance(ctx, req)
		if etagMismatch(callErr) {
			continue
		}
		if err := rpcErr(updated, callErr); err != nil {
			return nil, resource.Instance{}, err
		}
		return updated, model, nil
	}
	return nil, resource.Instance{}, resource.Conflict(resource.KindInstance, id.String(), "instance changed")
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
	labels, err := instanceUpdateLabels(
		model, inst.GetLabels(), resource.ActionAttachVolume, m.Fingerprint, nil, c.clock(),
	)
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
	vol.AttachState = resource.AttachmentAttaching
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
	requestHex := detachRequestHex(m.Key)
	// A retry of a detach this instance already took is that detach, even if
	// the volume was attached again since (EC2 client-token rules: the same
	// token and parameters succeed with no further action).
	if got != nil {
		if rec, ok := detachReplayFrom(got.GetLabels(), vol.ID.String()); ok && rec.requestHex == requestHex {
			rec.instanceID = model.ID
			switch rec.opMatch(m.Fingerprint) {
			case opSaved:
				return c.acceptDetachReplay(ctx, m.Account, vol, model, rec)
			case opOtherParams:
				return zero, resource.IdempotencyMismatch()
			case opUnknown:
				if !bound {
					return c.writeDetach(ctx, m, vol, got, model, backend.VolumeBind{
						InstanceID: rec.instanceID, Device: rec.device,
					}, false)
				}
			}
		}
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
	holder, holderModel, rec, ok, err := c.findDetachReplay(ctx, projectID, vol.ID, requestHex, req.InstanceID, got)
	if err != nil {
		return zero, err
	}
	if !ok {
		return zero, resource.Conflict(resource.KindVolume, vol.ID.String(), "volume is not in use")
	}
	switch rec.opMatch(m.Fingerprint) {
	case opSaved:
		return c.acceptDetachReplay(ctx, m.Account, vol, holderModel, rec)
	case opOtherParams:
		return zero, resource.IdempotencyMismatch()
	case opUnknown:
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

// findDetachReplay finds the record of request requestHex for volume id.
// detachOnce has already read the hint instance. A named instance is the only
// place a named request may replay. A volume-only request pages until an
// instance carries that request's record. A record of another request for the
// same volume, such as an older detach from another instance, is skipped.
func (c computeClient) findDetachReplay(
	ctx context.Context, projectID string, id resource.VolumeID, requestHex string, want resource.InstanceID,
	hint *computev1.Instance,
) (*computev1.Instance, resource.Instance, detachReplay, bool, error) {
	if hint != nil && !want.IsZero() {
		return nil, resource.Instance{}, detachReplay{}, false, nil
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
			if !ok || rec.requestHex != requestHex {
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
	now := c.clock()
	recordKey := labelDetachPrefix + vol.ID.String()
	var record map[string]string
	switch {
	case !drop:
		// This resends the update that wrote the record, by its request id,
		// so the records are the ones stored, stamps included.
		if stored, ok := got.GetLabels()[recordKey]; ok {
			record = map[string]string{recordKey: stored}
		}
	case m.MintedToken:
		// No caller can send this token again: no record, and an older
		// detach's record of this volume stays for that detach's retries.
	default:
		if detachRecordsInWindow(got.GetLabels(), now, vol.ID.String()) >= backend.MaxDetachReplays {
			return zero, backend.DetachReplaysExhausted(model.ID)
		}
		record = map[string]string{recordKey: detachRecordValue(detachRequestHex(m.Key), device, now)}
	}
	var labels map[string]string
	var err error
	if drop {
		labels, err = instanceUpdateLabels(
			model, got.GetLabels(), resource.ActionDetachVolume, m.Fingerprint, record, now,
		)
	} else {
		// The resend must be the update that was written, byte for byte, or
		// compute answers a fingerprint mismatch. So nothing is pruned: a
		// record that expired since is carried over as that write stored it.
		labels, err = instanceLabels(
			model, got.GetLabels(), resource.ActionDetachVolume, m.Fingerprint, storedDetachRecords(got.GetLabels()),
		)
	}
	if err != nil {
		return zero, err
	}
	if record != nil {
		// The operation id saved for this volume belongs to the previous
		// detach. Next to this request's record it would replay that detach,
		// so it goes. This request's own id is written by persistDetachOp.
		delete(labels, labelDetachOpPrefix+vol.ID.String())
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
	if !m.MintedToken {
		if err := c.persistDetachOp(ctx, m, got.GetName(), vol.ID.String(), op.ID.Local()); err != nil {
			return zero, err
		}
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
	requestHex := detachRequestHex(m.Key)
	value := opLocal + " " + detachFPToken(requestHex, m.Fingerprint)
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
		// A later detach of this volume owns the record now. This id would
		// pair with its request, so it is not written; a retry of this
		// request then asks compute by request id (detachOnce, opUnknown).
		if rec, ok := detachReplayFrom(got.GetLabels(), volID); !ok || rec.requestHex != requestHex {
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
// It carries the detach records over, pruned at now (pruneDetachRecords), so
// every label write frees the room of records no retry can need any more.
func instanceUpdateLabels(
	inst resource.Instance, raw map[string]string, action resource.Action, fingerprint string,
	record map[string]string, now time.Time,
) (map[string]string, error) {
	records := pruneDetachRecords(raw, now)
	maps.Copy(records, record)
	return instanceLabels(inst, raw, action, fingerprint, records)
}

// instanceLabels is instanceUpdateLabels with the detach records given as
// they are to be written, pruned or not.
func instanceLabels(
	inst resource.Instance, raw map[string]string, action resource.Action, fingerprint string,
	records map[string]string,
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
	maps.Copy(extra, records)
	return withInternalLabels(inst.Tags, extra)
}

// storedDetachRecords returns the detach records and saved operation ids of
// raw unchanged: no pruning and no stamping.
func storedDetachRecords(raw map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range raw {
		if strings.HasPrefix(key, labelDetachPrefix) || strings.HasPrefix(key, labelDetachOpPrefix) {
			out[key] = value
		}
	}
	return out
}

// A detach record value is "<request hex> <device> <stamp>": the stamp is
// the time the detach was accepted, in base-36 Unix seconds rounded up, so
// it is never earlier than the time compute starts remembering the request
// id (PR #316 review). A record
// written before #303 has no stamp, and neither does one whose device name
// leaves no room for it in a 63-byte label value.
func detachRecordValue(requestHex, device string, at time.Time) string {
	plain := requestHex + " " + device
	sec := at.Unix()
	if at.Nanosecond() > 0 {
		sec++
	}
	if stamped := plain + " " + strconv.FormatInt(sec, 36); len(stamped) <= labelValueMax {
		return stamped
	}
	return plain
}

// parseDetachRecord reads a detach record value. ok is false for a value no
// request can match.
func parseDetachRecord(raw string) (requestHex, device string, at time.Time, stamped, ok bool) {
	parts := strings.Split(raw, " ")
	switch len(parts) {
	case 2:
	case 3:
		n, err := strconv.ParseInt(parts[2], 36, 64)
		if err != nil || n <= 0 {
			return "", "", time.Time{}, false, false
		}
		at, stamped = time.Unix(n, 0).UTC(), true
	default:
		return "", "", time.Time{}, false, false
	}
	if parts[0] == "" {
		return "", "", time.Time{}, false, false
	}
	return parts[0], parts[1], at, stamped, true
}

// pruneDetachRecords returns the detach records of raw, with their saved
// operation ids, that a retry may still need at now (#303). A record that
// has expired (backend.ClientTokenExpired: more than the window and its
// grace past the stamp) is dropped with its operation id: the request id it
// would replay is past compute's window too. While a recovery is pending
// (detachRecoveryPending), expired records are kept as stored: the pending
// detach's retry resends its original update, which carried them, and must
// match it byte for byte (#319 review). A record with no
// stamp is stamped now, so its window starts at the first write that sees
// it. A stamp ahead of now is clock skew and is kept. An operation id with
// no record, and a value no request can match, are dropped. The result
// depends only on raw and now, so pruning twice changes nothing.
func pruneDetachRecords(raw map[string]string, now time.Time) map[string]string {
	hold := detachRecoveryPending(raw, now)
	out := map[string]string{}
	for key, value := range raw {
		volID, ok := strings.CutPrefix(key, labelDetachPrefix)
		if !ok {
			continue
		}
		requestHex, device, at, stamped, ok := parseDetachRecord(value)
		if !ok {
			continue
		}
		if !stamped {
			value = detachRecordValue(requestHex, device, now)
		} else if !hold && backend.ClientTokenExpired(at, now) {
			continue
		}
		out[key] = value
		if op, ok := raw[labelDetachOpPrefix+volID]; ok {
			out[labelDetachOpPrefix+volID] = op
		}
	}
	return out
}

// detachRecoveryPending reports whether raw holds a detach record within the
// window at now with no saved operation id: a detach whose operation id
// write failed, so its retry resends the original update by request id. It
// ends when that id is saved or the record expires.
func detachRecoveryPending(raw map[string]string, now time.Time) bool {
	for key, value := range raw {
		volID, ok := strings.CutPrefix(key, labelDetachPrefix)
		if !ok {
			continue
		}
		_, _, at, stamped, ok := parseDetachRecord(value)
		if !ok || (stamped && backend.ClientTokenExpired(at, now)) {
			continue
		}
		if _, saved := raw[labelDetachOpPrefix+volID]; !saved {
			return true
		}
	}
	return false
}

// Every user tag EC2 allows and every detach record within the window fit
// next to the internal labels, whose count withInternalLabels reserves: two
// labels per record (vws-detach-, vws-dop-). The array length is negative,
// and the build fails, if a limit changes so they no longer fit (#303).
var _ [labelMax - resource.MaxTags - labelReserve - 2*backend.MaxDetachReplays]struct{}

// detachRecordsInWindow counts the records a retry may still need at now,
// apart from one for skipVolID, which a new detach of that volume replaces.
// An expired record kept for a pending recovery is not within the window,
// so it does not count toward backend.MaxDetachReplays.
func detachRecordsInWindow(raw map[string]string, now time.Time, skipVolID string) int {
	n := 0
	for key, value := range pruneDetachRecords(raw, now) {
		volID, ok := strings.CutPrefix(key, labelDetachPrefix)
		if !ok || volID == skipVolID {
			continue
		}
		if _, _, at, stamped, _ := parseDetachRecord(value); stamped && backend.ClientTokenExpired(at, now) {
			continue
		}
		n++
	}
	return n
}

func detachRequestHex(key string) string {
	return strings.ReplaceAll(requestUUID(key, "detach"), "-", "")
}

// detachFPToken binds a saved operation id to the request and its
// fingerprint, so it can only replay for that request. The label value stays
// "<op> <16 hex>" and fits in 63 bytes for any operation id length.
func detachFPToken(requestHex, fingerprint string) string {
	sum := sha256.Sum256([]byte(requestHex + "\x00" + fingerprint))
	return hex.EncodeToString(sum[:8])
}

// legacyFPToken is the token written before #213, bound to the fingerprint
// only. Such a record may pair an older detach's operation with this request.
func legacyFPToken(fingerprint string) string {
	sum := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(sum[:8])
}

// opMatch is what a saved operation id means for a retry.
type opMatch int

const (
	// opUnknown: no id is saved for this request, or it cannot be trusted.
	// The retry asks compute by request id.
	opUnknown opMatch = iota
	// opSaved: the id is this request's, with the same parameters.
	opSaved
	// opOtherParams: the token was used with other parameters.
	opOtherParams
)

// opMatch compares the saved operation token with this request's fingerprint.
func (r detachReplay) opMatch(fingerprint string) opMatch {
	switch {
	case r.opLocal == "":
		return opUnknown
	case r.fingerprint == detachFPToken(r.requestHex, fingerprint):
		return opSaved
	case r.fingerprint == legacyFPToken(fingerprint):
		return opUnknown
	default:
		return opOtherParams
	}
}

func detachRecordKey(key string) bool {
	return strings.HasPrefix(key, labelDetachPrefix) || strings.HasPrefix(key, labelDetachOpPrefix)
}

func detachReplayFrom(labels map[string]string, volID string) (detachReplay, bool) {
	raw, ok := labels[labelDetachPrefix+volID]
	if !ok {
		return detachReplay{}, false
	}
	requestHex, device, _, _, ok := parseDetachRecord(raw)
	if !ok {
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
		if err := c.markAttaching(ctx, s.Account, items); err != nil {
			return resource.Page[resource.Volume]{}, err
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
			if c.skipBadRecord(ctx, item.GetName(), err) {
				continue
			}
			return resource.Page[resource.Volume]{}, err
		}
		items = append(items, vol)
	}
	if err := c.markAttaching(ctx, s.Account, items); err != nil {
		return resource.Page[resource.Volume]{}, err
	}
	return resource.Page[resource.Volume]{Items: items, NextToken: out.GetNextPageToken()}, nil
}

// markAttaching shows an accepted attach that storage does not report yet.
// AttachVolume writes the volume into the instance spec, and storage names
// the instance only once compute has put the disk on the machine, so for a
// while the volume reads as available. The spec is the attachment, as for
// DetachVolume: a volume that storage reports with no instance and that a
// live instance spec names is in-use, attaching. It lists instances only when
// some volume reads as available, and fails rather than show such a volume
// as available when compute cannot be read.
func (c computeClient) markAttaching(ctx context.Context, account resource.AccountID, items []resource.Volume) error {
	free := 0
	for _, v := range items {
		if v.State == resource.VolumeAvailable && v.InstanceID.IsZero() {
			free++
		}
	}
	if free == 0 {
		return nil
	}
	binds, err := c.specBinds(ctx, account)
	if err != nil {
		return err
	}
	for i := range items {
		v := &items[i]
		if v.State != resource.VolumeAvailable || !v.InstanceID.IsZero() {
			continue
		}
		bind, ok := binds[v.ID]
		if !ok || bind.Boot {
			continue
		}
		v.State = resource.VolumeInUse
		v.InstanceID = bind.InstanceID
		v.Device = bind.Device
		v.AttachState = resource.AttachmentAttaching
	}
	return nil
}

// specBinds maps each volume a live instance spec names to that bind. It
// pages all of the caller's instances; a repeated page token is an error.
// A terminated instance holds no volume. A record owned by another account
// is an internal error, never the caller's attachment. A list that runs out
// of time is Unavailable, so the read can be retried.
func (c computeClient) specBinds(
	ctx context.Context, account resource.AccountID,
) (map[resource.VolumeID]backend.VolumeBind, error) {
	projectID := project(account)
	out := map[resource.VolumeID]backend.VolumeBind{}
	token := ""
	seen := map[string]struct{}{}
	for {
		if token != "" {
			if _, ok := seen[token]; ok {
				return nil, resource.Internal(errors.New("instance page token repeated"))
			}
			seen[token] = struct{}{}
		}
		page, err := c.instances.ListInstances(ctx, &computev1.ListInstancesRequest{
			Parent: instanceParent(projectID), PageSize: 100, PageToken: token,
		})
		if status.Code(err) == codes.DeadlineExceeded {
			return nil, &resource.Error{Code: resource.CodeUnavailable, Message: "instance list timed out"}
		}
		if err != nil {
			return nil, fromRPC(err)
		}
		for _, item := range page.GetInstances() {
			model, err := instanceModel(item)
			if err != nil {
				if c.skipBadRecord(ctx, item.GetName(), err) {
					continue
				}
				return nil, err
			}
			if model.OwnerID != account {
				return nil, resource.Internal(errors.New("instance " + item.GetName() + " is owned by another account"))
			}
			if model.State == resource.InstanceTerminated {
				continue
			}
			for _, block := range model.BlockDevices {
				if bind, ok := backend.BindOf(model, block.VolumeID); ok {
					out[block.VolumeID] = bind
				}
			}
		}
		token = page.GetNextPageToken()
		if token == "" {
			return out, nil
		}
	}
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
	}
	projectID := project(m.Account)
	keyPairID, err := c.keyPairID(ctx, projectID, m.Account, req.Name)
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	if req.PublicKey == "" {
		// The key comes from crypto/rand and nothing else, so no request
		// input can rebuild it. It is never stored or logged.
		if pair, err = sshkey.Generate(req.Type, rand.Reader); err != nil {
			return resource.Accepted[resource.KeyPair]{}, resource.Internal(err)
		}
	}
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
	requestID := requestUUID(m.Key, "key")
	// reused is an import that names the request of the key pair it found
	// live at keyPairID, so compute may answer it from that request's record.
	reused := false
	if req.PublicKey == "" {
		// EC2 CreateKeyPair takes no client token (#268). Each attempt is its
		// own compute request, named by the token and the new public key, so
		// compute's record of an earlier create under the token never answers
		// it. A gRPC retry of this attempt resends the same request id.
		requestID = requestUUID(m.Key, "key", pair.Public)
	} else {
		nonce, held, err := c.importNonce(ctx, projectID, keyPairID)
		if err != nil {
			return resource.Accepted[resource.KeyPair]{}, err
		}
		reused = held
		if nonce != "" {
			labels[labelImport] = nonce
			requestID = requestUUID(m.Key, "key", nonce)
		}
	}
	submit := func() (*longrunningpb.Operation, error) {
		return c.keys.CreateKeyPair(ctx, &computev1.CreateKeyPairRequest{
			Parent:    regionParent(projectID),
			KeyPairId: keyPairID,
			RequestId: requestID,
			KeyPair: &computev1.KeyPair{
				Labels: labels,
				Spec:   &computev1.KeyPairSpec{PublicKey: pair.Public},
			},
		})
	}
	created, err := submit()
	for attempt := 0; req.PublicKey != ""; attempt++ {
		answer := rpcErr(created, err)
		next, again, nerr := c.nextImport(ctx, projectID, keyPairID, labels, pair.AWSFingerprint, reused, answer)
		if nerr != nil {
			return resource.Accepted[resource.KeyPair]{}, nerr
		}
		if !again {
			break
		}
		if attempt == maxImportAttempts {
			// Deletes and imports of the name keep landing between this
			// import's steps. Report it as retryable rather than guess.
			return resource.Accepted[resource.KeyPair]{}, &resource.Error{
				Code: resource.CodeUnavailable, Kind: resource.KindKeyPair, ID: req.Name,
				Message: "the key pair changed during the import; retry",
			}
		}
		reused = next.reused
		requestID = requestUUID(m.Key, "key")
		delete(labels, labelImport)
		if next.nonce != "" {
			labels[labelImport] = next.nonce
			requestID = requestUUID(m.Key, "key", next.nonce)
		}
		created, err = submit()
	}
	if rerr := rpcErr(created, err); rerr != nil {
		// Only a name collision is InvalidKeyPair.Duplicate (#284). The key
		// pair id is derived from the name, so ALREADY_EXISTS is one. An
		// import's IDEMPOTENCY_CONFLICT is one only when it named the request
		// of the key pair live at that id: the token's other body for a live
		// name. Any other conflict keeps its own code.
		code := resource.CodeOf(rerr)
		if code == resource.CodeAlreadyExists || (reused && code == resource.CodeIdempotencyMismatch) {
			return resource.Accepted[resource.KeyPair]{}, resource.AlreadyExists(resource.KindKeyPair, req.Name)
		}
		return resource.Accepted[resource.KeyPair]{}, keyPairConflict(created, err, rerr, req.Name)
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
	projectID := project(m.Account)
	current, err := c.findGroup(ctx, projectID, req.ID.String())
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	for _, have := range current.Rules {
		if have == req.Rule {
			return resource.Accepted[resource.SecurityGroup]{}, resource.AlreadyExists(resource.KindSecurityGroup, current.ID.String())
		}
	}
	rules := append(append([]resource.IngressRule{}, current.Rules...), req.Rule)
	protoRules := make([]*networkv1.SecurityGroupRule, 0, len(rules))
	for i, rule := range rules {
		protoRule, err := ruleProto(rule, derivedID("r", m.Key, "rule", hex.EncodeToString([]byte{byte(i)})))
		if err != nil {
			return resource.Accepted[resource.SecurityGroup]{}, err
		}
		protoRules = append(protoRules, protoRule)
	}
	updated, err := c.groups.UpdateSecurityGroup(ctx, &networkv1.UpdateSecurityGroupRequest{
		RequestId:  requestUUID(m.Key, "ingress"),
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.rules"}},
		SecurityGroup: &networkv1.SecurityGroup{
			Name: securityGroupName(projectID, current.VpcID.String(), current.ID.String()),
			Spec: &networkv1.SecurityGroupSpec{Rules: protoRules},
		},
	})
	if err := rpcErr(updated, err); err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	op, err := operationFrom(updated, resource.ServiceNetwork)
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	got, err := c.findGroup(ctx, projectID, req.ID.String())
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	op.Action = resource.ActionAuthorizeSecurityGroupIngress
	op.Targets = []resource.Ref{got.ID.Ref()}
	return resource.Accepted[resource.SecurityGroup]{Operation: op, Items: []resource.SecurityGroup{got}}, nil
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
	token := ""
	for page := 0; page < 20; page++ {
		out, err := c.vpcs.ListVpcs(ctx, &networkv1.ListVpcsRequest{
			Parent: regionParent(projectID), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return resource.SecurityGroup{}, fromRPC(err)
		}
		for _, vpc := range out.GetVpcs() {
			got, err := c.groups.GetSecurityGroup(ctx, &networkv1.GetSecurityGroupRequest{
				Name: vpc.GetName() + "/securityGroups/" + id,
			})
			if err != nil {
				if resource.CodeOf(fromRPC(err)) == resource.CodeNotFound {
					continue
				}
				return resource.SecurityGroup{}, fromRPC(err)
			}
			return groupModel(got)
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return resource.SecurityGroup{}, resource.NotFound(resource.KindSecurityGroup, id)
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
		return resource.Volume{}, resource.Internal(&badRecordNameError{errors.New("bad volume name")})
	}
	id, err := resource.Parse[resource.VolumeID](parts[5])
	if err != nil {
		return resource.Volume{}, resource.Internal(&badRecordNameError{err})
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.Volume{}, resource.Internal(&badRecordNameError{err})
	}
	state := volumeStateOf(in)
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
	if !vol.InstanceID.IsZero() {
		// Storage names the instance once the disk is on the machine.
		vol.AttachState = resource.AttachmentAttached
	}
	return vol, nil
}

func volumeStateOf(in *storagev1.Volume) resource.VolumeState {
	obs := in.GetStatus().GetObserved().GetState()
	// A failed volume is error, which EC2 reports even for an attached volume.
	if reconcileFailed(obs) {
		return resource.VolumeError
	}
	if in.GetStatus().GetInstance() != "" {
		return resource.VolumeInUse
	}
	switch obs {
	case commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING, commonv1.ReconciliationState_RECONCILIATION_STATE_RECONCILING:
		return resource.VolumeCreating
	case commonv1.ReconciliationState_RECONCILIATION_STATE_READY:
		return resource.VolumeAvailable
	case commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING:
		return resource.VolumeDeleting
	case commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR,
		commonv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED:
		return resource.VolumeError
	default:
		return resource.VolumeError
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
	// Storage reports the instance once compute has put the disk on the
	// machine, not when the attach is accepted.
	if !v.InstanceID.IsZero() && v.AttachState != resource.AttachmentAttaching {
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

// keyPairID names the key pair a create asks compute for. It is always the
// id derived from the account and the name, so compute's atomic create of
// that id is the one reservation of the name: two creates of a live name
// cannot both succeed, even when they race (#273).
//
// A key pair made before #273 carries an id derived from its client token,
// which that reservation cannot see. Such a key pair still holds its name,
// so a create that finds it is InvalidKeyPair.Duplicate. The create never
// targets the legacy id: a create that did would succeed once the legacy
// key pair was deleted, while another create took the derived id (#278).
// No new legacy id is ever made, so a legacy key pair that is gone stays
// gone, and the name-derived id is the only id a create can win.
func (c computeClient) keyPairID(
	ctx context.Context, projectID string, account resource.AccountID, name string,
) (string, error) {
	id := derivedID("key-", account.String(), "key-name", name)
	held, err := c.findKey(ctx, projectID, resource.DeleteKeyPairRequest{Name: name})
	switch {
	case err == nil && held.ID.String() != id:
		return "", resource.AlreadyExists(resource.KindKeyPair, name)
	case err == nil, missingResource(err):
		return id, nil
	default:
		return "", err
	}
}

// importNonce picks the nonce of an import's compute request id (#279). EC2
// ImportKeyPair takes no client token, but an in-flight retry must not make a
// second key pair. While a key pair lives at id, the retry reuses its nonce,
// so the same token and body name the same compute request and compute
// replays it; any other import of the live name is refused. A key pair made
// before #279 has no nonce, so its retry keeps the old request id. held
// reports that a key pair lived at id. When id is free, the import gets a new
// random nonce: compute's retained record of an import whose key pair was
// deleted can no longer answer it.
func (c computeClient) importNonce(ctx context.Context, projectID, id string) (nonce string, held bool, err error) {
	name := keyPairName(projectID, id)
	kp, err := c.keys.GetKeyPair(ctx, &computev1.GetKeyPairRequest{Name: name})
	switch {
	case err == nil:
		return kp.GetLabels()[labelImport], true, nil
	case !missingResource(fromNamedRPC(name, err)):
		return "", false, fromNamedRPC(name, err)
	}
	nonce, err = newNonce()
	return nonce, false, err
}

func newNonce() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", resource.Internal(err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// keyPairConflict names the EC2 error for a compute conflict on a key pair
// create (#291). mapped is the client's reading of compute's answer, which
// is the gRPC error rpc or the error of the finished operation op.
//
// ETAG_MISMATCH, GENERATION_CONFLICT and Aborted without a reason mean
// compute lost an optimistic concurrency race. That is transient, so it is
// Unavailable, which EC2 documents as a retryable server error. Every other
// conflict (DEPENDENCY_NOT_READY, DEPENDENCY_MISSING, FailedPrecondition
// without a reason) refuses the create in the current state, which EC2
// documents as IncorrectState. Both name the key pair, so neither reads as
// an instance error. Other errors are returned as they are.
func keyPairConflict(op *longrunningpb.Operation, rpc, mapped error, name string) error {
	if resource.CodeOf(mapped) != resource.CodeConflict {
		return mapped
	}
	raw := rpc
	if raw == nil && op.GetError() != nil {
		raw = status.ErrorProto(op.GetError())
	}
	st, _ := status.FromError(raw)
	out := &resource.Error{Code: resource.CodeConflict, Kind: resource.KindKeyPair, ID: name, Message: st.Message()}
	if out.Message == "" {
		out.Message = "the key pair cannot be created in its current state"
	}
	switch vwsReason(st) {
	case "ETAG_MISMATCH", "GENERATION_CONFLICT":
		out.Code = resource.CodeUnavailable
	case "":
		if st.Code() == codes.Aborted {
			out.Code = resource.CodeUnavailable
		}
	}
	return out
}

// vwsReason is the vws.dev ErrorInfo reason of st, or "" when it has none.
func vwsReason(st *status.Status) string {
	for _, detail := range st.Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok && info.GetDomain() == "vws.dev" {
			return info.GetReason()
		}
	}
	return ""
}

// staleImport reports whether compute answered an import that reused a live
// key pair's request from the record of a key pair deleted since (#284).
// Such an answer is a replay or IDEMPOTENCY_CONFLICT. The import is current
// only while a key pair still lives at id; a replay also needs it to be this
// request's key pair: same key, same token fingerprint, same nonce.
func (c computeClient) staleImport(
	ctx context.Context, projectID, id string, labels map[string]string, fingerprint string, replayed bool,
) (bool, error) {
	name := keyPairName(projectID, id)
	kp, err := c.keys.GetKeyPair(ctx, &computev1.GetKeyPairRequest{Name: name})
	if err != nil {
		named := fromNamedRPC(name, err)
		if missingResource(named) {
			return true, nil
		}
		return false, named
	}
	if !replayed {
		return false, nil
	}
	live := kp.GetLabels()
	held, perr := sshkey.ParsePublic(kp.GetSpec().GetPublicKey())
	same := perr == nil && held.AWSFingerprint == fingerprint &&
		live[labelFingerprint] == labels[labelFingerprint] && live[labelImport] == labels[labelImport]
	return !same, nil
}

// maxImportAttempts bounds how often one ImportKeyPair resubmits after a
// racing delete or import changed the key pair under it.
const maxImportAttempts = 3

// importStep is the request an import sends next: the nonce its request id
// is named by, and whether that nonce belongs to a key pair seen live.
type importStep struct {
	nonce  string
	reused bool
}

// nextImport judges compute's answer to an import and picks what, if
// anything, to send next.
//
// After a request that reused a live key pair's nonce, a replay or
// IDEMPOTENCY_CONFLICT may come from the record of a key pair deleted since;
// then the import runs again under a new nonce (#284).
//
// After a request under a new nonce, ALREADY_EXISTS means another import or
// create took the name first. An identical import under the same token that
// raced this one is the same import, so the request is sent again under the
// winner's nonce: compute replays the winner's request when token and body
// match, and refuses it otherwise, so a winner under another token or with
// another key is still InvalidKeyPair.Duplicate (#287). If the winner is
// gone already, the name was taken when compute answered, and the answer
// stands.
func (c computeClient) nextImport(
	ctx context.Context, projectID, id string, labels map[string]string, fingerprint string, reused bool, answer error,
) (importStep, bool, error) {
	code := resource.CodeOf(answer)
	if reused {
		if answer != nil && code != resource.CodeIdempotencyMismatch {
			return importStep{}, false, nil
		}
		stale, err := c.staleImport(ctx, projectID, id, labels, fingerprint, answer == nil)
		if err != nil || !stale {
			return importStep{}, false, err
		}
		nonce, err := newNonce()
		return importStep{nonce: nonce}, err == nil, err
	}
	if code != resource.CodeAlreadyExists {
		return importStep{}, false, nil
	}
	nonce, held, err := c.importNonce(ctx, projectID, id)
	if err != nil || !held {
		return importStep{}, false, err
	}
	return importStep{nonce: nonce, reused: true}, true, nil
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
