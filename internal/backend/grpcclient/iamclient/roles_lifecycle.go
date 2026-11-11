package iamclient

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TrustPolicyAttempts bounds the read-modify-write of UpdateAssumeRolePolicy:
// each attempt reads the role and writes under its etag, and a write that
// loses the etag race reads again. After the last lost race the answer is
// AWS ConcurrentModification.
const TrustPolicyAttempts = 3

// CreateRole implements iam.Admin over RoleService.CreateRole. The request is
// checked as the fake checks it before anything is sent, and one request id
// covers every retry, so a retry after a lost reply is not a second role.
func (a STSAdmin) CreateRole(
	ctx context.Context, account resource.AccountID, in iam.RoleInput,
) (out iam.Role, err error) {
	ctx, end := a.observe(ctx, "CreateRole", true, account, "", "")
	defer func() { end(err) }()
	in, err = iam.CheckRoleInput(in)
	if err != nil {
		return iam.Role{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	op, err := retry(ctx, a.backoff, a.roles.CreateRole, &iamv1.CreateRoleRequest{
		Parent: projectName(account), RoleId: in.Name, RequestId: newRequestID(),
		Role: &iamv1.Role{Spec: &iamv1.RoleSpec{
			Path: in.Path, AssumeRolePolicy: in.TrustPolicy, Description: in.Description,
			MaxSessionDurationSeconds: int32(in.MaxSessionDuration), //nolint:gosec // CheckRoleInput bounds it to 43200.
		}},
	})
	if err != nil {
		return iam.Role{}, roleError(err, in.Name)
	}
	if err := roleOpError(op, in.Name); err != nil {
		return iam.Role{}, err
	}
	var role iamv1.Role
	if resp := op.GetResponse(); resp == nil || resp.UnmarshalTo(&role) != nil {
		return iam.Role{}, resource.Internal(errors.New("vws-iam CreateRole returned no role"))
	}
	out = roleFromProto(&role, in.Name)
	if out.ARN == "" {
		return iam.Role{}, resource.Internal(errors.New("vws-iam CreateRole returned a role with no ARN"))
	}
	return out, nil
}

// ListRoles implements iam.Admin over every page of RoleService.ListRoles,
// sorted by name and filtered by path prefix ("" is every path).
func (a STSAdmin) ListRoles(
	ctx context.Context, account resource.AccountID, prefix string,
) (out []iam.Role, err error) {
	ctx, end := a.observe(ctx, "ListRoles", false, account, "", "")
	defer func() { end(err) }()
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	out = []iam.Role{}
	token := ""
	for range maxListPages {
		resp, err := retry(ctx, a.backoff, a.roles.ListRoles, &iamv1.ListRolesRequest{
			Parent: projectName(account), PageSize: listPageSize, PageToken: token,
		})
		if err != nil {
			return nil, roleError(err, "")
		}
		for _, r := range resp.GetRoles() {
			got := roleFromProto(r, "")
			if got.ARN == "" {
				return nil, resource.Internal(errors.New("vws-iam ListRoles returned a role with no ARN"))
			}
			if strings.HasPrefix(got.Path, prefixOrRoot(prefix)) {
				out = append(out, got)
			}
		}
		if token = resp.GetNextPageToken(); token == "" {
			sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
			return out, nil
		}
	}
	return nil, resource.Internal(fmt.Errorf("vws-iam ListRoles has more than %d pages", maxListPages))
}

// UpdateAssumeRolePolicy implements iam.Admin as a read-modify-write of
// spec.assume_role_policy under the role's etag. want must be the role's ARN
// at every read. A write that loses the etag race reads the role again, up
// to TrustPolicyAttempts times; each attempt has its own request id, and its
// retries after a lost reply reuse it.
func (a STSAdmin) UpdateAssumeRolePolicy(
	ctx context.Context, account resource.AccountID, name, document string, want iam.AuthorizedPrincipal,
) (err error) {
	if err := want.Require(); err != nil {
		return err
	}
	ctx, end := a.observe(ctx, "UpdateAssumeRolePolicy", true, account, "", "")
	defer func() { end(err) }()
	if err := iam.ValidateTrustPolicy(document); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	for range TrustPolicyAttempts {
		role, err := a.roleAt(ctx, account, name, want)
		if err != nil {
			return err
		}
		if iam.IsServiceLinkedRole(role.GetSpec().GetPath()) {
			return iam.UnmodifiableRole(name)
		}
		op, err := retry(ctx, a.backoff, a.roles.UpdateRole, &iamv1.UpdateRoleRequest{
			Role: &iamv1.Role{
				Name: roleName(account, name), Etag: role.GetEtag(),
				Spec: &iamv1.RoleSpec{AssumeRolePolicy: document},
			},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.assume_role_policy"}},
			RequestId:  newRequestID(),
		})
		if err == nil {
			err = roleOpError(op, name)
		} else {
			err = roleError(err, name)
		}
		if !iam.IsChanged(err) {
			return err
		}
	}
	return iam.Changed(iam.RoleChanged)
}

// DeleteRole implements iam.Admin over RoleService.DeleteRole. want must be
// the role's ARN when it is read, and the delete carries that read's etag, so
// a role changed in between is ConcurrentModification, not deleted.
func (a STSAdmin) DeleteRole(
	ctx context.Context, account resource.AccountID, name string, want iam.AuthorizedPrincipal,
) (err error) {
	if err := want.Require(); err != nil {
		return err
	}
	ctx, end := a.observe(ctx, "DeleteRole", true, account, "", "")
	defer func() { end(err) }()
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	role, err := a.roleAt(ctx, account, name, want)
	if err != nil {
		return err
	}
	if iam.IsServiceLinkedRole(role.GetSpec().GetPath()) {
		return iam.UnmodifiableRole(name)
	}
	op, err := retry(ctx, a.backoff, a.roles.DeleteRole, &iamv1.DeleteRoleRequest{
		Name: roleName(account, name), Etag: role.GetEtag(), RequestId: newRequestID(),
	})
	if err != nil {
		return roleError(err, name)
	}
	return roleOpError(op, name)
}

// roleError maps a vws-iam role error to AWS: NotFound is NoSuchEntity,
// AlreadyExists is EntityAlreadyExists, a lost etag race is
// ConcurrentModification, and the rest (MalformedPolicyDocument,
// DeleteConflict, UnmodifiableEntity, ...) is authError's.
func roleError(err error, name string) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() { //nolint:exhaustive // the rest is authError's.
	case codes.NotFound:
		return iam.EntityNotFound("role", name)
	case codes.AlreadyExists:
		return iam.EntityExists("Role", name)
	case codes.Aborted:
		return iam.Changed(iam.RoleChanged)
	case codes.FailedPrecondition:
		for _, d := range st.Details() {
			if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetMetadata()["aws_code"] == "ConcurrentModification" {
				return iam.Changed(iam.RoleChanged)
			}
		}
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
		return backendUnavailable(err)
	}
	return authError(err)
}

// roleOpError is the error of a done vws-iam role operation, mapped as
// roleError.
func roleOpError(op *longrunningpb.Operation, name string) error {
	switch {
	case op == nil:
		return resource.Internal(errors.New("vws-iam returned no operation"))
	case !op.GetDone():
		return resource.Internal(errors.New("vws-iam returned a running operation"))
	case op.GetError() != nil:
		return roleError(status.ErrorProto(op.GetError()), name)
	}
	return nil
}
