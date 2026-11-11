package iamclient

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// RoleService of the directory stand-in, as vws-iam internal/grpcapi/roles.go
// serves it: names fold case, writes carry an etag (the version) and a
// request_id, a trust policy that is not JSON is MalformedPolicyDocument, a
// role with policies is DeleteConflict and a service-linked role is
// UnmodifiableEntity.

func (d *directory) roleProto(e *dirEntity) *iamv1.Role {
	project, _, _ := split(e.name, "roles")
	arn := entityARN(project, "role", e)
	if e.noARN {
		arn = ""
	}
	return &iamv1.Role{
		Name: e.name, Etag: strconv.Itoa(e.version),
		Spec: &iamv1.RoleSpec{
			Path: dirPath(e.path), AssumeRolePolicy: e.trust, Description: e.desc,
			MaxSessionDurationSeconds: e.maxSession, AttachedPolicies: policyNames(project, e.attached),
		},
		Status:     &iamv1.RoleStatus{Arn: arn, UniqueId: e.id},
		CreateTime: timestamppb.New(e.created),
	}
}

func trustArg(doc string) error {
	if doc == "" || !json.Valid([]byte(doc)) {
		return awsErr(codes.InvalidArgument, "MALFORMED_POLICY", "MalformedPolicyDocument")
	}
	return nil
}

func (d *directory) GetRole(_ context.Context, req *iamv1.GetRoleRequest) (*iamv1.Role, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("GetRole", req); err != nil {
		return nil, err
	}
	r := d.roles[fold(req.GetName())]
	if r == nil {
		return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	}
	return d.roleProto(r), nil
}

func (d *directory) ListRoles(_ context.Context, req *iamv1.ListRolesRequest) (*iamv1.ListRolesResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("ListRoles", req); err != nil {
		return nil, err
	}
	rs, next, err := page(d, d.roles, req.GetParent()+"/roles", req.GetPageSize(), req.GetPageToken(), d.roleProto)
	if err != nil {
		return nil, err
	}
	return &iamv1.ListRolesResponse{Roles: rs, NextPageToken: next}, nil
}

func (d *directory) CreateRole(_ context.Context, req *iamv1.CreateRoleRequest) (*longrunningpb.Operation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("CreateRole", req); err != nil {
		return nil, err
	}
	if op, found, err := d.replay("CreateRole", req.GetRequestId(), req); found {
		return op, err
	}
	if !dirNameRE.MatchString(req.GetRoleId()) {
		return nil, awsErr(codes.InvalidArgument, "INVALID_ARGUMENT", "ValidationError")
	}
	spec := req.GetRole().GetSpec()
	if err := checkPathArg(spec.GetPath()); err != nil {
		return nil, err
	}
	if err := trustArg(spec.GetAssumeRolePolicy()); err != nil {
		return nil, err
	}
	name := req.GetParent() + "/roles/" + req.GetRoleId()
	if d.roles[fold(name)] != nil {
		return nil, awsErr(codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists")
	}
	r := &dirEntity{
		name: name, path: spec.GetPath(), id: d.nextID("AROA"), created: time.Now().UTC(), version: 1,
		trust: spec.GetAssumeRolePolicy(), desc: spec.GetDescription(), maxSession: spec.GetMaxSessionDurationSeconds(),
	}
	d.roles[fold(name)] = r
	return d.done("CreateRole", req.GetRequestId(), req, d.roleProto(r))
}

// UpdateRole serves the spec.assume_role_policy mask only; that is all the
// role lifecycle sends through this stand-in.
func (d *directory) UpdateRole(_ context.Context, req *iamv1.UpdateRoleRequest) (*longrunningpb.Operation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("UpdateRole", req); err != nil {
		return nil, err
	}
	if op, found, err := d.replay("UpdateRole", req.GetRequestId(), req); found {
		return op, err
	}
	if p := req.GetUpdateMask().GetPaths(); len(p) != 1 || p[0] != "spec.assume_role_policy" {
		return nil, awsErr(codes.InvalidArgument, "INVALID_ARGUMENT", "ValidationError")
	}
	r := d.roles[fold(req.GetRole().GetName())]
	if r == nil {
		return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	}
	if d.roleRace > 0 {
		d.roleRace--
		r.version++ // another writer got there first
	}
	if e := req.GetRole().GetEtag(); e != "" && e != strconv.Itoa(r.version) {
		return nil, awsErr(codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
	}
	if err := trustArg(req.GetRole().GetSpec().GetAssumeRolePolicy()); err != nil {
		return nil, err
	}
	r.trust = req.GetRole().GetSpec().GetAssumeRolePolicy()
	r.version++
	return d.done("UpdateRole", req.GetRequestId(), req, d.roleProto(r))
}

func (d *directory) DeleteRole(_ context.Context, req *iamv1.DeleteRoleRequest) (*longrunningpb.Operation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("DeleteRole", req); err != nil {
		return nil, err
	}
	if op, found, err := d.replay("DeleteRole", req.GetRequestId(), req); found {
		return op, err
	}
	r := d.roles[fold(req.GetName())]
	if r == nil {
		return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	}
	if d.roleRace > 0 {
		d.roleRace--
		r.version++
	}
	if e := req.GetEtag(); e != "" && e != strconv.Itoa(r.version) {
		return nil, awsErr(codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
	}
	if len(r.attached) > 0 || len(r.inline) > 0 {
		return nil, awsErr(codes.FailedPrecondition, "DELETE_CONFLICT", "DeleteConflict")
	}
	delete(d.roles, fold(req.GetName()))
	return d.done("DeleteRole", req.GetRequestId(), req, nil)
}
