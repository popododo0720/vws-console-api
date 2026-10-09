package grpcclient

import (
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-console-api/internal/backend"
	commonv1 "github.com/popododo0720/vws-console-api/internal/backend/grpcclient/internal/pb/commonv1"
	computev1 "github.com/popododo0720/vws-console-api/internal/backend/grpcclient/internal/pb/computev1"
	networkv1 "github.com/popododo0720/vws-console-api/internal/backend/grpcclient/internal/pb/networkv1"
	storagev1 "github.com/popododo0720/vws-console-api/internal/backend/grpcclient/internal/pb/storagev1"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func scopeProto(s backend.Scope) *commonv1.Scope {
	return &commonv1.Scope{AccountId: s.Account.String()}
}

func mutationProto(m backend.Mutation) *commonv1.Mutation {
	return &commonv1.Mutation{Scope: scopeProto(m.Scope), Key: m.Key, Fingerprint: m.Fingerprint}
}

func scopeModel(s *commonv1.Scope) (backend.Scope, error) {
	if s == nil {
		return backend.Scope{}, resource.Invalid("account", "required")
	}
	account, err := resource.Parse[resource.AccountID](s.GetAccountId())
	if err != nil {
		return backend.Scope{}, err
	}
	return backend.Scope{Account: account}, nil
}

func mutationModel(m *commonv1.Mutation) (backend.Mutation, error) {
	if m == nil {
		return backend.Mutation{}, resource.Invalid("mutation", "required")
	}
	s, err := scopeModel(m.GetScope())
	if err != nil {
		return backend.Mutation{}, err
	}
	if m.GetKey() == "" || m.GetFingerprint() == "" {
		return backend.Mutation{}, resource.Invalid("mutation", "required")
	}
	return backend.Mutation{Scope: s, Key: m.GetKey(), Fingerprint: m.GetFingerprint()}, nil
}

func pageProto(p resource.PageRequest) *commonv1.Page {
	return &commonv1.Page{PageSize: int32(p.Size), PageToken: p.Token}
}

func pageModel(p *commonv1.Page) resource.PageRequest {
	if p == nil {
		return resource.PageRequest{}
	}
	return resource.PageRequest{Size: int(p.GetPageSize()), Token: p.GetPageToken()}
}

func operationProto(op resource.Operation) *commonv1.Operation {
	targets := make([]*commonv1.Target, 0, len(op.Targets))
	for _, target := range op.Targets {
		targets = append(targets, &commonv1.Target{Kind: target.Kind().String(), Id: target.ID()})
	}
	out := &commonv1.Operation{
		Id:         op.ID.String(),
		Action:     op.Action.String(),
		State:      op.State.String(),
		OwnerId:    op.OwnerID.String(),
		Targets:    targets,
		CreateTime: op.CreateTime.UTC().Format(time.RFC3339Nano),
		UpdateTime: op.UpdateTime.UTC().Format(time.RFC3339Nano),
	}
	if op.Error != nil {
		out.ErrorCode = op.Error.Code.String()
		out.ErrorMessage = op.Error.Message
	}
	return out
}

func operationModel(op *commonv1.Operation) (resource.Operation, error) {
	if op == nil {
		return resource.Operation{}, resource.Internal(errString("missing operation"))
	}
	id, err := resource.Parse[resource.OperationID](op.GetId())
	if err != nil {
		return resource.Operation{}, resource.Internal(err)
	}
	action, ok := resource.ParseAction(op.GetAction())
	if !ok {
		return resource.Operation{}, resource.Internal(errString("bad action"))
	}
	state, err := parseOpState(op.GetState())
	if err != nil {
		return resource.Operation{}, err
	}
	targets := make([]resource.Ref, 0, len(op.GetTargets()))
	for _, target := range op.GetTargets() {
		ref, err := resource.ParseRef(target.GetKind(), target.GetId())
		if err != nil {
			return resource.Operation{}, resource.Internal(err)
		}
		targets = append(targets, ref)
	}
	var owner resource.AccountID
	if op.GetOwnerId() != "" {
		owner, err = resource.Parse[resource.AccountID](op.GetOwnerId())
		if err != nil {
			return resource.Operation{}, resource.Internal(err)
		}
	}
	parsed := resource.Operation{ID: id, Action: action, State: state, OwnerID: owner, Targets: targets}
	if op.GetErrorCode() != "" {
		parsed.Error = &resource.Error{Code: codeByName(op.GetErrorCode()), Message: op.GetErrorMessage()}
	}
	if op.GetCreateTime() != "" {
		parsed.CreateTime, err = time.Parse(time.RFC3339Nano, op.GetCreateTime())
		if err != nil {
			return resource.Operation{}, resource.Internal(err)
		}
	}
	if op.GetUpdateTime() != "" {
		parsed.UpdateTime, err = time.Parse(time.RFC3339Nano, op.GetUpdateTime())
		if err != nil {
			return resource.Operation{}, resource.Internal(err)
		}
	}
	return parsed, nil
}

func parseOpState(s string) (resource.OperationState, error) {
	switch s {
	case resource.OperationRunning.String():
		return resource.OperationRunning, nil
	case resource.OperationSucceeded.String():
		return resource.OperationSucceeded, nil
	case resource.OperationFailed.String():
		return resource.OperationFailed, nil
	default:
		return 0, resource.Internal(errString("bad operation state"))
	}
}

func instanceProto(inst resource.Instance) *computev1.Instance {
	return &computev1.Instance{
		InstanceId:    inst.ID.String(),
		ReservationId: inst.ReservationID.String(),
		OwnerId:       inst.OwnerID.String(),
		State:         inst.State.String(),
		ImageId:       inst.ImageID.String(),
		InstanceType:  inst.InstanceType,
		SubnetId:      inst.SubnetID.String(),
		Zone:          inst.Zone,
		PrivateIp:     inst.PrivateIP,
		Tags:          inst.Tags,
	}
}

func instanceModel(in *computev1.Instance) (resource.Instance, error) {
	id, err := resource.Parse[resource.InstanceID](in.GetInstanceId())
	if err != nil {
		return resource.Instance{}, resource.Internal(err)
	}
	res, err := resource.Parse[resource.ReservationID](in.GetReservationId())
	if err != nil {
		return resource.Instance{}, resource.Internal(err)
	}
	owner, err := resource.Parse[resource.AccountID](in.GetOwnerId())
	if err != nil {
		return resource.Instance{}, resource.Internal(err)
	}
	img, err := resource.Parse[resource.ImageID](in.GetImageId())
	if err != nil {
		return resource.Instance{}, resource.Internal(err)
	}
	sub, err := resource.Parse[resource.SubnetID](in.GetSubnetId())
	if err != nil {
		return resource.Instance{}, resource.Internal(err)
	}
	state, ok := resource.ParseInstanceState(in.GetState())
	if !ok {
		return resource.Instance{}, resource.Internal(errString("bad instance state"))
	}
	return resource.Instance{
		ID: id, ReservationID: res, OwnerID: owner, State: state, ImageID: img,
		InstanceType: in.GetInstanceType(), SubnetID: sub, Zone: in.GetZone(),
		PrivateIP: in.GetPrivateIp(), Tags: in.GetTags(),
	}, nil
}

func subnetProto(s resource.Subnet) *networkv1.Subnet {
	return &networkv1.Subnet{SubnetId: s.ID.String(), OwnerId: s.OwnerID.String(), CidrBlock: s.Cidr, State: s.State.String()}
}

func subnetModel(in *networkv1.Subnet) (resource.Subnet, error) {
	id, err := resource.Parse[resource.SubnetID](in.GetSubnetId())
	if err != nil {
		return resource.Subnet{}, resource.Internal(err)
	}
	owner, err := resource.Parse[resource.AccountID](in.GetOwnerId())
	if err != nil {
		return resource.Subnet{}, resource.Internal(err)
	}
	var state resource.SubnetState
	switch in.GetState() {
	case resource.SubnetPending.String():
		state = resource.SubnetPending
	case resource.SubnetAvailable.String():
		state = resource.SubnetAvailable
	default:
		return resource.Subnet{}, resource.Internal(errString("bad subnet state"))
	}
	return resource.Subnet{ID: id, OwnerID: owner, Cidr: in.GetCidrBlock(), State: state}, nil
}

func bucketProto(b resource.Bucket) *storagev1.Bucket {
	return &storagev1.Bucket{Name: b.Name.String(), OwnerId: b.OwnerID.String(), CreationDate: b.CreationDate}
}

func bucketModel(in *storagev1.Bucket) (resource.Bucket, error) {
	name, err := resource.Parse[resource.BucketName](in.GetName())
	if err != nil {
		return resource.Bucket{}, resource.Internal(err)
	}
	owner, err := resource.Parse[resource.AccountID](in.GetOwnerId())
	if err != nil {
		return resource.Bucket{}, resource.Internal(err)
	}
	return resource.Bucket{Name: name, OwnerID: owner, CreationDate: in.GetCreationDate()}, nil
}

func objectProto(o resource.Object) *storagev1.Object {
	return &storagev1.Object{
		Bucket: o.Bucket.String(), Key: o.Key.String(), OwnerId: o.OwnerID.String(),
		Size: o.Size, Etag: o.ETag, ContentType: o.ContentType,
	}
}

func objectModel(in *storagev1.Object) (resource.Object, error) {
	bucket, err := resource.Parse[resource.BucketName](in.GetBucket())
	if err != nil {
		return resource.Object{}, resource.Internal(err)
	}
	key, err := resource.Parse[resource.ObjectKey](in.GetKey())
	if err != nil {
		return resource.Object{}, resource.Internal(err)
	}
	owner, err := resource.Parse[resource.AccountID](in.GetOwnerId())
	if err != nil {
		return resource.Object{}, resource.Internal(err)
	}
	return resource.Object{
		Bucket: bucket, Key: key, OwnerID: owner, Size: in.GetSize(), ETag: in.GetEtag(), ContentType: in.GetContentType(),
	}, nil
}

func toStatus(err error) error {
	if err == nil {
		return nil
	}
	e := resource.AsError(err)
	st, detailErr := status.New(grpcCode(e.Code), e.Message).WithDetails(&commonv1.Failure{
		Code: e.Code.String(), Kind: e.Kind.String(), Id: e.ID, Field: e.Field, Message: e.Message,
	})
	if detailErr != nil {
		return status.Error(codes.Internal, "internal error")
	}
	return st.Err()
}

func fromRPC(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return resource.Internal(err)
	}
	for _, detail := range st.Details() {
		failure, ok := detail.(*commonv1.Failure)
		if !ok {
			continue
		}
		return failureModel(failure)
	}
	return &resource.Error{Code: codeFromGRPC(st.Code()), Message: "backend request failed"}
}

func codeFromGRPC(c codes.Code) resource.Code {
	switch c {
	case codes.InvalidArgument:
		return resource.CodeInvalidArgument
	case codes.NotFound:
		return resource.CodeNotFound
	case codes.AlreadyExists:
		return resource.CodeAlreadyExists
	case codes.Aborted:
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
	case codes.Internal, codes.OK, codes.Canceled, codes.DeadlineExceeded, codes.Unknown, codes.FailedPrecondition, codes.OutOfRange, codes.DataLoss:
		return resource.CodeInternal
	default:
		return resource.CodeInternal
	}
}

func failureModel(f *commonv1.Failure) *resource.Error {
	return &resource.Error{Code: codeByName(f.GetCode()), Kind: kindByName(f.GetKind()), ID: f.GetId(), Field: f.GetField(), Message: f.GetMessage()}
}

func codeByName(s string) resource.Code {
	switch s {
	case resource.CodeInvalidArgument.String():
		return resource.CodeInvalidArgument
	case resource.CodeNotFound.String():
		return resource.CodeNotFound
	case resource.CodeAlreadyExists.String():
		return resource.CodeAlreadyExists
	case resource.CodeConflict.String():
		return resource.CodeConflict
	case resource.CodeIdempotencyMismatch.String():
		return resource.CodeIdempotencyMismatch
	case resource.CodeUnauthenticated.String():
		return resource.CodeUnauthenticated
	case resource.CodePermissionDenied.String():
		return resource.CodePermissionDenied
	case resource.CodeResourceExhausted.String():
		return resource.CodeResourceExhausted
	case resource.CodePayloadTooLarge.String():
		return resource.CodePayloadTooLarge
	case resource.CodeUnavailable.String():
		return resource.CodeUnavailable
	case resource.CodeUnimplemented.String():
		return resource.CodeUnimplemented
	case resource.CodeInternal.String():
		return resource.CodeInternal
	case resource.CodeUnspecified.String():
		return resource.CodeUnspecified
	default:
		return resource.CodeInternal
	}
}

func kindByName(s string) resource.Kind {
	if s == "" {
		return resource.KindUnspecified
	}
	for _, k := range resource.Kinds() {
		if k.String() == s {
			return k
		}
	}
	return resource.KindUnspecified
}

func grpcCode(c resource.Code) codes.Code {
	switch c {
	case resource.CodeInvalidArgument:
		return codes.InvalidArgument
	case resource.CodeNotFound:
		return codes.NotFound
	case resource.CodeAlreadyExists:
		return codes.AlreadyExists
	case resource.CodeConflict, resource.CodeIdempotencyMismatch:
		return codes.Aborted
	case resource.CodeUnauthenticated:
		return codes.Unauthenticated
	case resource.CodePermissionDenied:
		return codes.PermissionDenied
	case resource.CodeResourceExhausted:
		return codes.ResourceExhausted
	case resource.CodePayloadTooLarge:
		return codes.InvalidArgument
	case resource.CodeUnavailable:
		return codes.Unavailable
	case resource.CodeUnimplemented:
		return codes.Unimplemented
	case resource.CodeInternal, resource.CodeUnspecified:
		return codes.Internal
	default:
		return codes.Internal
	}
}

type strErr string

func (e strErr) Error() string { return string(e) }

func errString(s string) error { return strErr(s) }
