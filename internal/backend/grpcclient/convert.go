package grpcclient

import (
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
		return resource.Operation{}, resource.Internal(strErr("missing operation"))
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
		default:
			return 0, resource.Internal(strErr("unsupported operation"))
		}
	case commonv1.OperationVerb_OPERATION_VERB_UPDATE:
		switch {
		case containsSegment(resourceName, "instances"):
			return resource.ActionStopInstances, nil
		case containsSegment(resourceName, "securityGroups"):
			return resource.ActionAuthorizeSecurityGroupIngress, nil
		case containsSegment(resourceName, "volumes"):
			return resource.ActionAttachVolume, nil
		default:
			return 0, resource.Internal(strErr("unsupported operation"))
		}
	case commonv1.OperationVerb_OPERATION_VERB_DELETE:
		switch {
		case containsSegment(resourceName, "instances"):
			return resource.ActionTerminateInstances, nil
		case containsSegment(resourceName, "vpcs"):
			return resource.ActionDeleteVpc, nil
		case containsSegment(resourceName, "volumes"):
			return resource.ActionDeleteVolume, nil
		default:
			return 0, resource.Internal(strErr("unsupported operation"))
		}
	case commonv1.OperationVerb_OPERATION_VERB_UNSPECIFIED:
		return 0, resource.Internal(strErr("unsupported operation"))
	default:
		return 0, resource.Internal(strErr("unsupported operation"))
	}
}

func containsSegment(name, segment string) bool {
	return len(name) > 0 && (segmentOf(name, segment))
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
	default:
		return resource.Ref{}, false
	}
}

func metadataResource(op *longrunningpb.Operation) (string, error) {
	if op == nil || op.GetMetadata() == nil {
		return "", resource.Internal(strErr("missing operation"))
	}
	meta := &commonv1.OperationMetadata{}
	if err := op.GetMetadata().UnmarshalTo(meta); err != nil {
		return "", resource.Internal(err)
	}
	if meta.GetResource() == "" {
		return "", resource.Internal(strErr("missing operation"))
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
	obs, power := instanceObserved(inst.State)
	out := &computev1.Instance{
		Name: instanceName(projectID, inst.ID.String()),
		Labels: withInternalLabels(inst.Tags, map[string]string{
			labelImage:       inst.ImageID.String(),
			labelReservation: inst.ReservationID.String(),
		}),
		Spec: &computev1.InstanceSpec{
			MachineType: inst.InstanceType,
			Power:       power,
			NetworkInterfaces: []*computev1.NetworkInterface{{
				DeviceName: "nic0",
				Subnet:     subnetName(projectID, vpcID, inst.SubnetID.String()),
			}},
			Volumes: []*computev1.VolumeAttachment{{
				DeviceName: "boot",
				Boot:       true,
			}},
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
	if inst.State == resource.InstanceTerminated {
		out.DeleteTime = timestamppb.New(time.Unix(1, 0).UTC())
	}
	return out
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

func instanceModel(in *computev1.Instance) (resource.Instance, error) {
	if in == nil {
		return resource.Instance{}, resource.Internal(strErr("missing instance"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 6 || parts[2] != "zones" || parts[4] != "instances" {
		return resource.Instance{}, resource.Internal(strErr("bad instance name"))
	}
	id, err := resource.Parse[resource.InstanceID](parts[5])
	if err != nil {
		return resource.Instance{}, resource.Internal(err)
	}
	owner, err := accountOf(parts[1])
	if err != nil {
		return resource.Instance{}, err
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
		return resource.Instance{}, resource.Internal(strErr("missing subnet"))
	}
	sub, err := resource.Parse[resource.SubnetID](lastSegment(nics[0].GetSubnet()))
	if err != nil {
		return resource.Instance{}, resource.Internal(err)
	}
	state, err := instanceStateOf(in.GetStatus().GetObserved().GetState(), in.GetStatus().GetPower())
	if err != nil {
		return resource.Instance{}, err
	}
	if in.GetDeleteTime() != nil && state == resource.InstanceShuttingDown {
		state = resource.InstanceTerminated
	}
	private := ""
	if nics := in.GetStatus().GetNetworkInterfaces(); len(nics) > 0 {
		private = nics[0].GetPrivateIpv4()
	}
	return resource.Instance{
		ID: id, ReservationID: resID, OwnerID: owner, State: state, ImageID: img,
		InstanceType: in.GetSpec().GetMachineType(), SubnetID: sub, Zone: parts[3],
		PrivateIP: private, Tags: userTags(in.GetLabels()),
	}, nil
}

func instanceStateOf(obs commonv1.ReconciliationState, power computev1.InstancePower) (resource.InstanceState, error) {
	switch obs {
	case commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING:
		return resource.InstancePending, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_RECONCILING:
		if power == computev1.InstancePower_INSTANCE_POWER_STOPPED {
			return resource.InstanceStopping, nil
		}
		return resource.InstancePending, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_READY:
		if power == computev1.InstancePower_INSTANCE_POWER_STOPPED {
			return resource.InstanceStopped, nil
		}
		return resource.InstanceRunning, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING:
		return resource.InstanceShuttingDown, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR, commonv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED:
		return 0, resource.Internal(strErr("bad instance state"))
	default:
		return 0, resource.Internal(strErr("bad instance state"))
	}
}

func subnetProto(sub resource.Subnet, projectID, vpcID string) *networkv1.Subnet {
	obs := commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING
	if sub.State == resource.SubnetAvailable {
		obs = commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	}
	return &networkv1.Subnet{
		Name: subnetName(projectID, vpcID, sub.ID.String()),
		Spec: &networkv1.SubnetSpec{Zone: resource.ZoneName, Ipv4Cidr: sub.Cidr},
		Status: &networkv1.SubnetStatus{
			Observed: &commonv1.ObservedState{State: obs},
		},
	}
}

func subnetModel(in *networkv1.Subnet) (resource.Subnet, error) {
	if in == nil {
		return resource.Subnet{}, resource.Internal(strErr("missing subnet"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 8 || parts[6] != "subnets" {
		return resource.Subnet{}, resource.Internal(strErr("bad subnet name"))
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
	return resource.Subnet{ID: id, OwnerID: owner, VpcID: vpcID, Cidr: in.GetSpec().GetIpv4Cidr(), State: state}, nil
}

func subnetStateOf(obs commonv1.ReconciliationState) (resource.SubnetState, error) {
	switch obs {
	case commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING, commonv1.ReconciliationState_RECONCILIATION_STATE_RECONCILING:
		return resource.SubnetPending, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_READY:
		return resource.SubnetAvailable, nil
	case commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING, commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR, commonv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED:
		return 0, resource.Internal(strErr("bad subnet state"))
	default:
		return 0, resource.Internal(strErr("bad subnet state"))
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
		return resource.Bucket{}, resource.Internal(strErr("missing bucket"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 4 || parts[2] != "buckets" {
		return resource.Bucket{}, resource.Internal(strErr("bad bucket name"))
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
	return &storagev1.Object{
		Name: objectName(projectID, o.Bucket.String(), o.Key.String()),
		Etag: o.ETag,
		Spec: &storagev1.ObjectSpec{ContentType: o.ContentType},
		Status: &storagev1.ObjectStatus{
			Observed:  &commonv1.ObservedState{State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY},
			SizeBytes: o.Size,
		},
	}
}

func objectModel(in *storagev1.Object) (resource.Object, error) {
	if in == nil {
		return resource.Object{}, resource.Internal(strErr("missing object"))
	}
	parts := splitSlash(in.GetName())
	if len(parts) != 6 || parts[2] != "buckets" || parts[4] != "objects" {
		return resource.Object{}, resource.Internal(strErr("bad object name"))
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
	return resource.Object{
		Bucket: bucket, Key: key, OwnerID: owner,
		Size: in.GetStatus().GetSizeBytes(), ETag: in.GetEtag(), ContentType: in.GetSpec().GetContentType(),
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

type strErr string

func (e strErr) Error() string { return string(e) }
