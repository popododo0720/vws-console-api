package grpcclient

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func operationFrom(op *longrunningpb.Operation, svc resource.Service) (resource.Operation, error) {
	if op == nil {
		return resource.Operation{}, resource.Internal(errors.New("missing operation"))
	}
	local, err := operationLocal(op.GetName())
	if err != nil {
		return resource.Operation{}, err
	}
	id, err := resource.NewOperationID(svc, local)
	if err != nil {
		return resource.Operation{}, resource.Internal(err)
	}
	projectID, err := projectOfName(op.GetName())
	if err != nil {
		return resource.Operation{}, err
	}
	owner, err := accountOf(projectID)
	if err != nil {
		return resource.Operation{}, err
	}
	meta := &commonv1.OperationMetadata{}
	if op.GetMetadata() != nil {
		if err := op.GetMetadata().UnmarshalTo(meta); err != nil {
			return resource.Operation{}, resource.Internal(err)
		}
	}
	action, err := actionOf(meta.GetResource(), meta.GetVerb())
	if err != nil {
		return resource.Operation{}, err
	}
	state := resource.OperationRunning
	var opErr *resource.Error
	if op.GetDone() {
		state = resource.OperationSucceeded
		if op.GetError() != nil {
			state = resource.OperationFailed
			opErr = resource.AsError(fromRPC(status.ErrorProto(op.GetError())))
		}
	}
	parsed := resource.Operation{
		ID: id, Action: action, State: state, OwnerID: owner, Error: opErr,
	}
	if ref, ok := refFromResource(meta.GetResource()); ok {
		parsed.Targets = []resource.Ref{ref}
	}
	if meta.GetCreateTime() != nil {
		parsed.CreateTime = meta.GetCreateTime().AsTime().UTC()
	}
	if meta.GetEndTime() != nil {
		parsed.UpdateTime = meta.GetEndTime().AsTime().UTC()
	} else {
		parsed.UpdateTime = parsed.CreateTime
	}
	return parsed, nil
}

func actionOf(resourceName string, verb commonv1.OperationVerb) (resource.Action, error) {
	switch verb {
	case commonv1.OperationVerb_OPERATION_VERB_CREATE:
		switch {
		case containsSegment(resourceName, "instances"):
			return resource.ActionRunInstances, nil
		case containsSegment(resourceName, "subnets"):
			return resource.ActionCreateSubnet, nil
		case containsSegment(resourceName, "securityGroups"):
			return resource.ActionCreateSecurityGroup, nil
		case containsSegment(resourceName, "vpcs"):
			return resource.ActionCreateVpc, nil
		case containsSegment(resourceName, "volumes"):
			return resource.ActionCreateVolume, nil
		case containsSegment(resourceName, "keyPairs"):
			return resource.ActionCreateKeyPair, nil
		case containsSegment(resourceName, "addresses"):
			return resource.ActionAllocateAddress, nil
		case containsSegment(resourceName, "snapshots"):
			return resource.ActionCreateSnapshot, nil
		default:
			return 0, resource.Internal(errors.New("unsupported operation"))
		}
	case commonv1.OperationVerb_OPERATION_VERB_UPDATE:
		switch {
		case containsSegment(resourceName, "instances"):
			return resource.ActionStopInstances, nil
		case containsSegment(resourceName, "securityGroups"):
			return resource.ActionAuthorizeSecurityGroupIngress, nil
		case containsSegment(resourceName, "volumes"):
			// Attach is an instance update; the only volume update is a resize.
			return resource.ActionModifyVolume, nil
		case containsSegment(resourceName, "addresses"):
			return resource.ActionAssociateAddress, nil
		case containsSegment(resourceName, "subnets"), containsSegment(resourceName, "vpcs"):
			// vws-network serves only label updates on VPCs and subnets.
			return resource.ActionCreateTags, nil
		default:
			return 0, resource.Internal(errors.New("unsupported operation"))
		}
	case commonv1.OperationVerb_OPERATION_VERB_DELETE:
		switch {
		case containsSegment(resourceName, "instances"):
			return resource.ActionTerminateInstances, nil
		case containsSegment(resourceName, "subnets"):
			return resource.ActionDeleteSubnet, nil
		case containsSegment(resourceName, "securityGroups"):
			return resource.ActionDeleteSecurityGroup, nil
		case containsSegment(resourceName, "vpcs"):
			return resource.ActionDeleteVpc, nil
		case containsSegment(resourceName, "volumes"):
			return resource.ActionDeleteVolume, nil
		case containsSegment(resourceName, "keyPairs"):
			return resource.ActionDeleteKeyPair, nil
		case containsSegment(resourceName, "addresses"):
			return resource.ActionReleaseAddress, nil
		case containsSegment(resourceName, "snapshots"):
			return resource.ActionDeleteSnapshot, nil
		default:
			return 0, resource.Internal(errors.New("unsupported operation"))
		}
	case commonv1.OperationVerb_OPERATION_VERB_UNSPECIFIED:
		return 0, resource.Internal(errors.New("unsupported operation"))
	default:
		return 0, resource.Internal(errors.New("unsupported operation"))
	}
}

func containsSegment(name, segment string) bool {
	return len(name) > 0 && segmentOf(name, segment)
}

func segmentOf(name, segment string) bool {
	parts := splitSlash(name)
	for _, part := range parts {
		if part == segment {
			return true
		}
	}
	return false
}

func splitSlash(name string) []string {
	out := make([]string, 0, 8)
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '/' {
			if i > start {
				out = append(out, name[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func refFromResource(name string) (resource.Ref, bool) {
	parts := splitSlash(name)
	if len(parts) < 2 {
		return resource.Ref{}, false
	}
	kind := parts[len(parts)-2]
	id := parts[len(parts)-1]
	switch kind {
	case "instances":
		parsed, err := resource.Parse[resource.InstanceID](id)
		if err != nil {
			return resource.Ref{}, false
		}
		return parsed.Ref(), true
	case "subnets":
		parsed, err := resource.Parse[resource.SubnetID](id)
		if err != nil {
			return resource.Ref{}, false
		}
		return parsed.Ref(), true
	case "vpcs":
		parsed, err := resource.Parse[resource.VpcID](id)
		if err != nil {
			return resource.Ref{}, false
		}
		return parsed.Ref(), true
	case "volumes":
		parsed, err := resource.Parse[resource.VolumeID](id)
		if err != nil {
			return resource.Ref{}, false
		}
		return parsed.Ref(), true
	case "securityGroups":
		parsed, err := resource.Parse[resource.SecurityGroupID](id)
		if err != nil {
			return resource.Ref{}, false
		}
		return parsed.Ref(), true
	case "keyPairs":
		parsed, err := resource.Parse[resource.KeyPairID](id)
		if err != nil {
			return resource.Ref{}, false
		}
		return parsed.Ref(), true
	case "addresses":
		parsed, err := resource.Parse[resource.AddressID](id)
		if err != nil {
			return resource.Ref{}, false
		}
		return parsed.Ref(), true
	case "snapshots":
		parsed, err := resource.Parse[resource.SnapshotID](id)
		if err != nil {
			return resource.Ref{}, false
		}
		return parsed.Ref(), true
	default:
		return resource.Ref{}, false
	}
}

// operationRequestID is the request id vws-storage echoes in the operation
// metadata, or "" when it names none.
func operationRequestID(op *longrunningpb.Operation) (string, error) {
	if op.GetMetadata() == nil {
		return "", nil
	}
	meta := &commonv1.OperationMetadata{}
	if err := op.GetMetadata().UnmarshalTo(meta); err != nil {
		return "", resource.Internal(err)
	}
	return meta.GetRequestId(), nil
}

func metadataResource(op *longrunningpb.Operation) (string, error) {
	if op == nil || op.GetMetadata() == nil {
		return "", resource.Internal(errors.New("missing operation"))
	}
	meta := &commonv1.OperationMetadata{}
	if err := op.GetMetadata().UnmarshalTo(meta); err != nil {
		return "", resource.Internal(err)
	}
	if meta.GetResource() == "" {
		return "", resource.Internal(errors.New("missing operation"))
	}
	return meta.GetResource(), nil
}

func longOp(projectID, local, resourceName, requestID string, verb commonv1.OperationVerb, create time.Time) (*longrunningpb.Operation, error) {
	meta, err := anypb.New(&commonv1.OperationMetadata{
		Resource:   resourceName,
		Verb:       verb,
		RequestId:  requestID,
		CreateTime: timestamppb.New(create.UTC()),
	})
	if err != nil {
		return nil, resource.Internal(err)
	}
	return &longrunningpb.Operation{
		Name:     operationName(projectID, local),
		Metadata: meta,
	}, nil
}

func instanceProto(inst resource.Instance, projectID, vpcID string) *computev1.Instance {
	// The tags were accepted when the instance was made, so they fit.
	labels, _ := withInternalLabels(inst.Tags, map[string]string{ //nolint:errcheck // accepted tags fit
		labelImage:       inst.ImageID.String(),
		labelReservation: inst.ReservationID.String(),
	})
	obs, power := instanceObserved(inst.State)
	var created *timestamppb.Timestamp
	if !inst.LaunchTime.IsZero() {
		created = timestamppb.New(inst.LaunchTime)
	}
	out := &computev1.Instance{
		CreateTime: created,
		Name:       instanceName(projectID, inst.ID.String()),
		Labels:     labels,
		Spec: &computev1.InstanceSpec{
			MachineType: inst.InstanceType,
			Power:       power,
			UserData:    inst.UserData,
			NetworkInterfaces: []*computev1.NetworkInterface{{
				DeviceName: "nic0",
				Subnet:     subnetName(projectID, vpcID, inst.SubnetID.String()),
			}},
			Volumes: volumeAttachments(projectID, inst.BlockDevices),
		},
		Status: &computev1.InstanceStatus{
			Observed: &commonv1.ObservedState{State: obs},
			Power:    power,
			NetworkInterfaces: []*computev1.ObservedNetworkInterface{{
				DeviceName:  "nic0",
				Subnet:      subnetName(projectID, vpcID, inst.SubnetID.String()),
				PrivateIpv4: inst.PrivateIP,
			}},
		},
	}
	if !inst.KeyPairID.IsZero() {
		out.Spec.KeyPair = keyPairName(projectID, inst.KeyPairID.String())
	}
	if inst.State == resource.InstanceTerminated {
		out.DeleteTime = timestamppb.New(time.Unix(1, 0).UTC())
	}
	return out
}

// observedVolumes indexes InstanceStatus.volumes by volume id. A malformed
// volume name makes the record bad, so a listing skips it.
func observedVolumes(in *computev1.Instance) (map[resource.VolumeID]*computev1.ObservedVolumeAttachment, error) {
	out := map[resource.VolumeID]*computev1.ObservedVolumeAttachment{}
	for _, o := range in.GetStatus().GetVolumes() {
		id, err := resource.Parse[resource.VolumeID](lastSegment(o.GetVolume()))
		if err != nil {
			return nil, resource.Internal(&badRecordNameError{err})
		}
		out[id] = o
	}
	return out, nil
}

func instanceObserved(st resource.InstanceState) (commonv1.ReconciliationState, computev1.InstancePower) {
	switch st {
	case resource.InstancePending:
		return commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING, computev1.InstancePower_INSTANCE_POWER_RUNNING
	case resource.InstanceRunning:
		return commonv1.ReconciliationState_RECONCILIATION_STATE_READY, computev1.InstancePower_INSTANCE_POWER_RUNNING
	case resource.InstanceStopping:
		return commonv1.ReconciliationState_RECONCILIATION_STATE_RECONCILING, computev1.InstancePower_INSTANCE_POWER_STOPPED
	case resource.InstanceStopped:
		return commonv1.ReconciliationState_RECONCILIATION_STATE_READY, computev1.InstancePower_INSTANCE_POWER_STOPPED
	case resource.InstanceShuttingDown, resource.InstanceTerminated:
		return commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING, computev1.InstancePower_INSTANCE_POWER_STOPPED
	default:
		return commonv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED, computev1.InstancePower_INSTANCE_POWER_UNSPECIFIED
	}
}

// badRecordNameError marks a backend record whose resource name does not name an
// id. A listing skips it and logs; an explicit id read still fails.
type badRecordNameError struct{ err error }

func (e *badRecordNameError) Error() string { return e.err.Error() }

func (e *badRecordNameError) Unwrap() error { return e.err }

// unknownVolumeTypeError marks a stored volume whose storage type this build
// cannot name: UNSPECIFIED, or a type a later vws-proto added. Its type is
// never guessed. A listing skips it and logs, DeleteVolume and DetachVolume
// still reach it (#335 review, #337), and an id read or an action that needs
// the type answers UnknownVolumeType (#337).
type unknownVolumeTypeError struct {
	id  resource.VolumeID
	typ storagev1.VolumeType
}

func (e *unknownVolumeTypeError) Error() string {
	return "volume " + e.id.String() + " has unknown type " + e.typ.String()
}

// skipBadRecord reports whether err marks a record a listing must leave out.
// It logs the record's name so a skipped resource stays auditable.
func (a *api) skipBadRecord(ctx context.Context, name string, err error) bool {
	var bad *badRecordNameError
	if errors.As(err, &bad) {
		a.logger().WarnContext(ctx, "skipping a record with an invalid resource name",
			slog.String("name", name), slog.Any("err", err))
		return true
	}
	var typ *unknownVolumeTypeError
	if errors.As(err, &typ) {
		a.logger().WarnContext(ctx, "skipping a volume with an unknown volume type",
			slog.String("name", name), slog.String("type", typ.typ.String()))
		return true
	}
	return false
}

// imageModel maps one compute image. Compute serves an image under the
// caller's regional name, so the copy source is the only record of the project
// that owns it: a public image copied from another project's volume or snapshot
// names that project. A seed image registered from a file has no copy source,
// so it reads as the caller's own and private.
func imageModel(in *computev1.Image, caller resource.AccountID) (resource.Image, error) {
	if in == nil {
		return resource.Image{}, resource.Internal(errors.New("missing image"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != "regions" || parts[4] != "images" {
		return resource.Image{}, resource.Internal(&badRecordNameError{errors.New("bad image name")})
	}
	id, err := resource.Parse[resource.ImageID](parts[5])
	if err != nil {
		return resource.Image{}, resource.Internal(&badRecordNameError{err})
	}
	owner, err := imageOwner(in, caller)
	if err != nil {
		return resource.Image{}, err
	}
	name := in.GetSpec().GetFamily()
	if name == "" {
		name = id.String()
	}
	return resource.Image{
		ID: id, OwnerID: owner, Name: name, State: imageStateOf(in.GetStatus().GetObserved().GetState()),
		Public: owner != caller,
	}, nil
}

// imageOwner is the account of the image's copy source. A source in another
// project is a public image compute exposed to the caller. A source in the
// caller's project, or no source, is the caller's own image.
func imageOwner(in *computev1.Image, caller resource.AccountID) (resource.AccountID, error) {
	source := in.GetSpec().GetVolume()
	if source == "" {
		source = in.GetSpec().GetSnapshot()
	}
	if source == "" {
		return caller, nil
	}
	parts := splitSlash(source)
	if len(parts) != 6 || parts[0] != "projects" || parts[1] == "" {
		return resource.AccountID{}, resource.Internal(&badRecordNameError{errors.New("bad image source")})
	}
	switch {
	case parts[2] == "regions" && parts[4] == "snapshots":
	case parts[2] == "zones" && parts[4] == "volumes":
	default:
		return resource.AccountID{}, resource.Internal(&badRecordNameError{errors.New("bad image source")})
	}
	if parts[1] == project(caller) {
		return caller, nil
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.AccountID{}, resource.Internal(&badRecordNameError{err})
	}
	return owner, nil
}

// imageStateOf is the EC2 image state of a compute reconciliation state.
func imageStateOf(obs commonv1.ReconciliationState) string {
	switch obs {
	case commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING,
		commonv1.ReconciliationState_RECONCILIATION_STATE_RECONCILING:
		return "pending"
	case commonv1.ReconciliationState_RECONCILIATION_STATE_READY:
		return "available"
	case commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING:
		return "deregistered"
	case commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR:
		return "failed"
	case commonv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED:
		return "available"
	}
	return "available"
}

func instanceModel(in *computev1.Instance) (resource.Instance, error) {
	if in == nil {
		return resource.Instance{}, resource.Internal(errors.New("missing instance"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 6 || parts[2] != "zones" || parts[4] != "instances" {
		return resource.Instance{}, resource.Internal(&badRecordNameError{errors.New("bad instance name")})
	}
	id, err := resource.Parse[resource.InstanceID](parts[5])
	if err != nil {
		return resource.Instance{}, resource.Internal(&badRecordNameError{err})
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.Instance{}, resource.Internal(&badRecordNameError{err})
	}
	resID, err := resource.Parse[resource.ReservationID](in.GetLabels()[labelReservation])
	if err != nil {
		return resource.Instance{}, resource.Internal(err)
	}
	img, err := resource.Parse[resource.ImageID](in.GetLabels()[labelImage])
	if err != nil {
		return resource.Instance{}, resource.Internal(err)
	}
	nics := in.GetSpec().GetNetworkInterfaces()
	if len(nics) == 0 {
		return resource.Instance{}, resource.Internal(errors.New("missing subnet"))
	}
	sub, err := resource.Parse[resource.SubnetID](lastSegment(nics[0].GetSubnet()))
	if err != nil {
		return resource.Instance{}, resource.Internal(err)
	}
	// The subnet name is .../vpcs/{vpc}/subnets/{subnet}. A subnet outside a
	// user VPC has a segment that is not a VPC id, and the field stays empty.
	var vpcID resource.VpcID
	if parts := strings.Split(nics[0].GetSubnet(), "/"); len(parts) == 8 {
		if parsed, perr := resource.Parse[resource.VpcID](parts[5]); perr == nil {
			vpcID = parsed
		}
	}
	observed := in.GetStatus().GetObserved().GetState()
	state := instanceStateOf(observed, in.GetStatus().GetPower())
	var reason resource.StateReason
	if reconcileFailed(observed) {
		reason = resource.StateReason{
			Code:    resource.ServerInternalError,
			Message: resource.ServerInternalErrorMessage,
		}
	}
	if in.GetDeleteTime() != nil && state == resource.InstanceShuttingDown {
		state = resource.InstanceTerminated
	}
	var keyPairID resource.KeyPairID
	if name := in.GetSpec().GetKeyPair(); name != "" {
		if keyPairID, err = resource.Parse[resource.KeyPairID](lastSegment(name)); err != nil {
			return resource.Instance{}, resource.Internal(err)
		}
	}
	attach, err := observedVolumes(in)
	if err != nil {
		return resource.Instance{}, err
	}
	var rootDevice string
	var blocks []resource.BlockDevice
	for _, v := range in.GetSpec().GetVolumes() {
		volID, err := resource.Parse[resource.VolumeID](lastSegment(v.GetVolume()))
		if err != nil {
			return resource.Instance{}, resource.Internal(err)
		}
		device := v.GetDeviceName()
		if v.GetBoot() {
			device, rootDevice = resource.RootDeviceName, resource.RootDeviceName
		}
		// A spec volume compute has no entry for is attaching: the node has
		// not started the attach yet (instance.proto, #448).
		state := resource.AttachmentAttaching
		if o, ok := attach[volID]; ok {
			state = attachStateOf(o.GetState())
		}
		blocks = append(blocks, resource.BlockDevice{
			Device: device, VolumeID: volID, DeleteOnTermination: v.GetBoot(), Status: state,
		})
	}
	private := ""
	if nics := in.GetStatus().GetNetworkInterfaces(); len(nics) > 0 {
		private = nics[0].GetPrivateIpv4()
	}
	return resource.Instance{
		ID: id, ReservationID: resID, OwnerID: owner, State: state, StateReason: reason, ImageID: img,
		InstanceType: in.GetSpec().GetMachineType(), SubnetID: sub, VpcID: vpcID, Zone: parts[3],
		LaunchTime: launchTime(in), PrivateIP: private, Tags: userTags(in.GetLabels()),
		KeyPairID: keyPairID, UserData: in.GetSpec().GetUserData(),
		RootDeviceName: rootDevice, BlockDevices: blocks,
	}, nil
}

func instanceStateOf(obs commonv1.ReconciliationState, power computev1.InstancePower) resource.InstanceState {
	switch obs {
	case commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING:
		return resource.InstancePending
	case commonv1.ReconciliationState_RECONCILIATION_STATE_RECONCILING:
		if power == computev1.InstancePower_INSTANCE_POWER_STOPPED {
			return resource.InstanceStopping
		}
		return resource.InstancePending
	case commonv1.ReconciliationState_RECONCILIATION_STATE_READY:
		if power == computev1.InstancePower_INSTANCE_POWER_STOPPED {
			return resource.InstanceStopped
		}
		return resource.InstanceRunning
	case commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING:
		return resource.InstanceShuttingDown
	case commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR,
		commonv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED:
		// EC2 has no error instance state. An internal launch failure is terminated.
		return resource.InstanceTerminated
	default:
		return resource.InstanceTerminated
	}
}

// reconcileFailed reports a record whose service failed it or cannot name its
// state. Compute and storage send UNSPECIFIED only for a lifecycle they do not
// know. Such a record is listed as failed so it cannot fail the listing (#191).
func reconcileFailed(obs commonv1.ReconciliationState) bool {
	switch obs {
	case commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING,
		commonv1.ReconciliationState_RECONCILIATION_STATE_RECONCILING,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING:
		return false
	case commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR,
		commonv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED:
		return true
	default:
		return true
	}
}

func subnetProto(sub resource.Subnet, projectID, vpcID string) *networkv1.Subnet {
	obs := commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING
	switch sub.State {
	case resource.SubnetAvailable:
		obs = commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	case resource.SubnetDeleting:
		obs = commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING
	case resource.SubnetPending:
	default:
	}
	// The tags were accepted when they were stored, so they fit.
	labels, _ := withInternalLabels(sub.Tags, nil) //nolint:errcheck // accepted tags fit
	return &networkv1.Subnet{
		Name:   subnetName(projectID, vpcID, sub.ID.String()),
		Labels: labels,
		Spec:   &networkv1.SubnetSpec{Zone: resource.ZoneName, Ipv4Cidr: sub.Cidr},
		Status: &networkv1.SubnetStatus{
			Observed: &commonv1.ObservedState{State: obs},
		},
	}
}

func subnetModel(in *networkv1.Subnet) (resource.Subnet, error) {
	if in == nil {
		return resource.Subnet{}, resource.Internal(errors.New("missing subnet"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 8 || parts[6] != "subnets" {
		return resource.Subnet{}, resource.Internal(errors.New("bad subnet name"))
	}
	id, err := resource.Parse[resource.SubnetID](parts[7])
	if err != nil {
		return resource.Subnet{}, resource.Internal(err)
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.Subnet{}, err
	}
	state, err := subnetStateOf(in.GetStatus().GetObserved().GetState())
	if err != nil {
		return resource.Subnet{}, err
	}
	var vpcID resource.VpcID
	if parsed, parseErr := resource.Parse[resource.VpcID](parts[5]); parseErr == nil {
		vpcID = parsed
	}
	return resource.Subnet{ID: id, OwnerID: owner, VpcID: vpcID, Cidr: in.GetSpec().GetIpv4Cidr(), State: state, Zone: in.GetSpec().GetZone(), Tags: userTags(in.GetLabels())}, nil
}

func subnetStateOf(obs commonv1.ReconciliationState) (resource.SubnetState, error) {
	switch obs {
	case commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING, commonv1.ReconciliationState_RECONCILIATION_STATE_RECONCILING:
		return resource.SubnetPending, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_READY:
		return resource.SubnetAvailable, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING:
		return resource.SubnetDeleting, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR, commonv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED:
		return 0, resource.Internal(errors.New("bad subnet state"))
	default:
		return 0, resource.Internal(errors.New("bad subnet state"))
	}
}

func bucketProto(b resource.Bucket, projectID string) *storagev1.Bucket {
	out := &storagev1.Bucket{
		Name: bucketName(projectID, b.Name.String()),
		Spec: &storagev1.BucketSpec{Region: resource.RegionName},
		Status: &storagev1.BucketStatus{
			Observed: &commonv1.ObservedState{State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY},
		},
	}
	if ts, err := time.Parse(time.RFC3339, b.CreationDate); err == nil {
		out.CreateTime = timestamppb.New(ts)
	}
	return out
}

func bucketModel(in *storagev1.Bucket) (resource.Bucket, error) {
	if in == nil {
		return resource.Bucket{}, resource.Internal(errors.New("missing bucket"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 4 || parts[2] != "buckets" {
		return resource.Bucket{}, resource.Internal(errors.New("bad bucket name"))
	}
	name, err := resource.Parse[resource.BucketName](parts[3])
	if err != nil {
		return resource.Bucket{}, resource.Internal(err)
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.Bucket{}, err
	}
	created := ""
	if in.GetCreateTime() != nil {
		created = in.GetCreateTime().AsTime().UTC().Format(time.RFC3339)
	}
	return resource.Bucket{Name: name, OwnerID: owner, CreationDate: created}, nil
}

func objectProto(o resource.Object, projectID string) *storagev1.Object {
	out := &storagev1.Object{
		Name: objectName(projectID, o.Bucket.String(), o.Key.String()),
		Etag: o.ETag,
		Spec: &storagev1.ObjectSpec{ContentType: o.ContentType, Sha256: o.SHA256},
		Status: &storagev1.ObjectStatus{
			Md5:       strings.Trim(o.ETag, `"`),
			Observed:  &commonv1.ObservedState{State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY},
			SizeBytes: o.Size,
		},
	}
	if ts, err := time.Parse(time.RFC3339, o.LastModified); err == nil {
		out.UpdateTime = timestamppb.New(ts)
	}
	return out
}

// s3ETag is the quoted MD5. The service fills status.md5 once the put
// operation is done. Before that the ETag is empty.
func s3ETag(md5 string) string {
	if md5 == "" {
		return ""
	}
	return `"` + md5 + `"`
}

func objectModel(in *storagev1.Object) (resource.Object, error) {
	if in == nil {
		return resource.Object{}, resource.Internal(errors.New("missing object"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 6 || parts[2] != "buckets" || parts[4] != "objects" {
		return resource.Object{}, resource.Internal(errors.New("bad object name"))
	}
	bucket, err := resource.Parse[resource.BucketName](parts[3])
	if err != nil {
		return resource.Object{}, resource.Internal(err)
	}
	keyText, err := decodeObjectKey(parts[5])
	if err != nil {
		return resource.Object{}, err
	}
	key, err := resource.Parse[resource.ObjectKey](keyText)
	if err != nil {
		return resource.Object{}, resource.Internal(err)
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.Object{}, err
	}
	modified := ""
	when := in.GetUpdateTime()
	if when == nil {
		when = in.GetCreateTime()
	}
	if when != nil {
		modified = when.AsTime().UTC().Format(time.RFC3339)
	}
	return resource.Object{
		Bucket: bucket, Key: key, OwnerID: owner,
		Size: in.GetStatus().GetSizeBytes(), ETag: s3ETag(in.GetStatus().GetMd5()), ContentType: in.GetSpec().GetContentType(),
		LastModified: modified, SHA256: in.GetSpec().GetSha256(),
	}, nil
}

func toStatus(err error) error {
	if err == nil {
		return nil
	}
	e := resource.AsError(err)
	reason, code, recon := errorDetail(e.Code)
	info := &errdetails.ErrorInfo{Reason: reason, Domain: "vws.dev"}
	var st *status.Status
	var detailErr error
	if recon != nil {
		st, detailErr = status.New(code, e.Message).WithDetails(info, recon)
	} else {
		st, detailErr = status.New(code, e.Message).WithDetails(info)
	}
	if detailErr != nil {
		return status.Error(codes.Internal, "internal error")
	}
	return st.Err()
}

func errorDetail(c resource.Code) (string, codes.Code, *commonv1.ReconciliationFailure) {
	switch c {
	case resource.CodeInvalidArgument, resource.CodePayloadTooLarge:
		return "INVALID_SPEC", codes.InvalidArgument, nil
	case resource.CodeNotFound:
		return "RESOURCE_NOT_FOUND", codes.NotFound, nil
	case resource.CodeAlreadyExists:
		return "ALREADY_EXISTS", codes.AlreadyExists, nil
	case resource.CodeConflict:
		return "DEPENDENCY_NOT_READY", codes.FailedPrecondition, nil
	case resource.CodeIdempotencyMismatch:
		return "IDEMPOTENCY_CONFLICT", codes.Aborted, nil
	case resource.CodeUnauthenticated:
		return "ERROR_REASON_UNSPECIFIED", codes.Unauthenticated, nil
	case resource.CodePermissionDenied:
		return "ERROR_REASON_UNSPECIFIED", codes.PermissionDenied, nil
	case resource.CodeResourceExhausted:
		return "QUOTA_EXCEEDED", codes.ResourceExhausted, nil
	case resource.CodeUnavailable:
		return "RECONCILIATION_FAILED", codes.Unavailable, &commonv1.ReconciliationFailure{Retryable: true}
	case resource.CodeUnimplemented:
		return "ERROR_REASON_UNSPECIFIED", codes.Unimplemented, nil
	case resource.CodeInternal, resource.CodeUnspecified:
		return "RECONCILIATION_FAILED", codes.Internal, &commonv1.ReconciliationFailure{Retryable: false}
	default:
		return "RECONCILIATION_FAILED", codes.Internal, &commonv1.ReconciliationFailure{Retryable: false}
	}
}

// etagMismatch reports a compare-and-swap failure for a stale resource etag.
func etagMismatch(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	for _, detail := range st.Details() {
		info, isInfo := detail.(*errdetails.ErrorInfo)
		if isInfo && info.GetReason() == "ETAG_MISMATCH" {
			return true
		}
	}
	return false
}

func fromRPC(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return resource.Internal(err)
	}
	var info *errdetails.ErrorInfo
	var recon *commonv1.ReconciliationFailure
	for _, detail := range st.Details() {
		switch typed := detail.(type) {
		case *errdetails.ErrorInfo:
			info = typed
		case *commonv1.ReconciliationFailure:
			recon = typed
		}
	}
	msg := st.Message()
	if msg == "" {
		msg = "backend request failed"
	}
	if info != nil && info.GetDomain() == "vws.dev" {
		return reasonError(info.GetReason(), recon, msg, st.Code())
	}
	return &resource.Error{Code: codeFromGRPC(st.Code()), Message: msg}
}

func reasonError(reason string, recon *commonv1.ReconciliationFailure, msg string, code codes.Code) *resource.Error {
	if id, ok := refusedImageID(msg); ok && missingImage(reason, code) {
		return &resource.Error{
			Code:    resource.CodeNotFound,
			Kind:    resource.KindImage,
			Message: "The image id '[" + id + "]' does not exist",
		}
	}
	switch reason {
	case "RESOURCE_NOT_FOUND":
		return &resource.Error{Code: resource.CodeNotFound, Message: msg}
	case "ALREADY_EXISTS":
		return &resource.Error{Code: resource.CodeAlreadyExists, Message: msg}
	case "INVALID_RESOURCE_ID", "INVALID_SPEC":
		return &resource.Error{Code: resource.CodeInvalidArgument, Message: msg}
	case "IDEMPOTENCY_CONFLICT":
		return &resource.Error{Code: resource.CodeIdempotencyMismatch, Message: msg}
	case "ETAG_MISMATCH", "GENERATION_CONFLICT", "DEPENDENCY_NOT_READY", "DEPENDENCY_MISSING":
		return &resource.Error{Code: resource.CodeConflict, Message: msg}
	case "QUOTA_EXCEEDED":
		return &resource.Error{Code: resource.CodeResourceExhausted, Message: msg}
	case "RECONCILIATION_FAILED":
		if recon != nil && recon.GetRetryable() {
			return &resource.Error{Code: resource.CodeUnavailable, Message: msg}
		}
		return &resource.Error{Code: resource.CodeInternal, Message: msg}
	default:
		return &resource.Error{Code: codeFromGRPC(code), Message: msg}
	}
}

// missingImage is the live RunInstances path and the storage operation it wraps.
// Compute returns VOLUME_FAILED after the boot volume's storage NOT_FOUND.
// Storage itself returns code 5 RECONCILIATION_FAILED for the same image.
func missingImage(reason string, code codes.Code) bool {
	return reason == "VOLUME_FAILED" || (reason == "RECONCILIATION_FAILED" && code == codes.NotFound)
}

// refusedImageID reads the public AMI id from an "image <name> not found" sentence.
// The name may be a resource path, and the sentence may follow a volume prefix.
// A name that is not an AMI id does not match.
func refusedImageID(msg string) (string, bool) {
	_, rest, ok := strings.Cut(msg, "image ")
	if !ok {
		return "", false
	}
	name, ok := strings.CutSuffix(rest, " not found")
	if !ok || name == "" || strings.ContainsAny(name, " \t") {
		return "", false
	}
	id, err := resource.Parse[resource.ImageID](lastSegment(name))
	if err != nil {
		return "", false
	}
	return id.String(), true
}

func codeFromGRPC(c codes.Code) resource.Code {
	switch c {
	case codes.InvalidArgument:
		return resource.CodeInvalidArgument
	case codes.NotFound:
		return resource.CodeNotFound
	case codes.AlreadyExists:
		return resource.CodeAlreadyExists
	case codes.Aborted, codes.FailedPrecondition:
		return resource.CodeConflict
	case codes.Unauthenticated:
		return resource.CodeUnauthenticated
	case codes.PermissionDenied:
		return resource.CodePermissionDenied
	case codes.ResourceExhausted:
		return resource.CodeResourceExhausted
	case codes.Unavailable:
		return resource.CodeUnavailable
	case codes.Unimplemented:
		return resource.CodeUnimplemented
	case codes.OK, codes.Canceled, codes.Unknown, codes.DeadlineExceeded, codes.OutOfRange, codes.Internal, codes.DataLoss:
		return resource.CodeInternal
	default:
		return resource.CodeInternal
	}
}

// fromNamedRPC is fromRPC for a call on one named resource. The VWS services
// report a missing resource as RESOURCE_NOT_FOUND without saying which kind,
// so the kind comes from the collection in the name the client sent.
func fromNamedRPC(name string, err error) error {
	mapped := fromRPC(err)
	if e := resource.AsError(mapped); e == nil || e.Code != resource.CodeNotFound || e.Kind != resource.KindUnspecified {
		return mapped
	}
	parent, id := name[:max(strings.LastIndex(name, "/"), 0)], lastSegment(name)
	collection := lastSegment(parent)
	for _, row := range []struct {
		collection string
		kind       resource.Kind
	}{
		{"instances", resource.KindInstance},
		{"volumes", resource.KindVolume},
		{"snapshots", resource.KindSnapshot},
		{"images", resource.KindImage},
		{"keyPairs", resource.KindKeyPair},
		{"vpcs", resource.KindVpc},
		{"subnets", resource.KindSubnet},
		{"securityGroups", resource.KindSecurityGroup},
		{"addresses", resource.KindAddress},
	} {
		if row.collection == collection {
			return resource.NotFound(row.kind, id)
		}
	}
	return mapped
}

// launchTime is compute's create_time, or zero when compute did not report one.
func launchTime(in *computev1.Instance) time.Time {
	if in.GetCreateTime() == nil {
		return time.Time{}
	}
	return in.GetCreateTime().AsTime().UTC()
}

func volumeAttachments(projectID string, blocks []resource.BlockDevice) []*computev1.VolumeAttachment {
	out := make([]*computev1.VolumeAttachment, 0, len(blocks))
	for _, b := range blocks {
		boot := b.Device == resource.RootDeviceName
		device := b.Device
		if boot {
			device = "boot"
		}
		out = append(out, &computev1.VolumeAttachment{Volume: volumeName(projectID, b.VolumeID.String()), DeviceName: device, Boot: boot})
	}
	return out
}
