package iamclient

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// STSAdmin serves the IAM Query surface's STS calls over vws-iam. Most IAM
// management calls are not mapped to vws-iam's User, Group, Role, Policy and
// AccessKey services yet; each answers Unimplemented, which the surface
// returns as InvalidAction. ListPolicyVersions, SetDefaultPolicyVersion, the
// policy and MFA device tag calls, GetRole and UpdateRoleDescription are
// mapped.
type STSAdmin struct{ *Client }

var _ iam.Admin = STSAdmin{}

func notServed(op string) error {
	return resource.Unimplemented(op + " is not served over vws-iam gRPC yet")
}

// CreateUser implements iam.Admin.
func (STSAdmin) CreateUser(_ context.Context, _ resource.AccountID, _, _ string) (iam.User, error) {
	return iam.User{}, notServed("CreateUser")
}

// GetUser implements iam.Admin.
func (STSAdmin) GetUser(_ context.Context, _ resource.AccountID, _ string) (iam.User, error) {
	return iam.User{}, notServed("GetUser")
}

// ListUsers implements iam.Admin.
func (STSAdmin) ListUsers(_ context.Context, _ resource.AccountID, _ string) ([]iam.User, error) {
	return nil, notServed("ListUsers")
}

// DeleteUser implements iam.Admin.
func (STSAdmin) DeleteUser(_ context.Context, _ resource.AccountID, _ string) error {
	return notServed("DeleteUser")
}

// UpdateUser implements iam.Admin.
func (STSAdmin) UpdateUser(_ context.Context, _ resource.AccountID, _, _, _, _ string) error {
	return notServed("UpdateUser")
}

// CreateAccessKey implements iam.Admin.
func (STSAdmin) CreateAccessKey(_ context.Context, _ resource.AccountID, _ string) (iam.NewAccessKey, error) {
	return iam.NewAccessKey{}, notServed("CreateAccessKey")
}

// ListAccessKeys implements iam.Admin.
func (STSAdmin) ListAccessKeys(_ context.Context, _ resource.AccountID, _ string) ([]iam.AccessKeyMeta, error) {
	return nil, notServed("ListAccessKeys")
}

// DeleteAccessKey implements iam.Admin.
func (STSAdmin) DeleteAccessKey(_ context.Context, _ resource.AccountID, _, _ string) error {
	return notServed("DeleteAccessKey")
}

// CreateGroup implements iam.Admin.
func (STSAdmin) CreateGroup(_ context.Context, _ resource.AccountID, _, _ string) (iam.Group, error) {
	return iam.Group{}, notServed("CreateGroup")
}

// GetGroup implements iam.Admin.
func (STSAdmin) GetGroup(_ context.Context, _ resource.AccountID, _ string) (iam.Group, []iam.User, error) {
	return iam.Group{}, nil, notServed("GetGroup")
}

// ListGroups implements iam.Admin.
func (STSAdmin) ListGroups(_ context.Context, _ resource.AccountID, _ string) ([]iam.Group, error) {
	return nil, notServed("ListGroups")
}

// UpdateGroup implements iam.Admin.
func (STSAdmin) UpdateGroup(_ context.Context, _ resource.AccountID, _, _, _ string) error {
	return notServed("UpdateGroup")
}

// DeleteGroup implements iam.Admin.
func (STSAdmin) DeleteGroup(_ context.Context, _ resource.AccountID, _ string) error {
	return notServed("DeleteGroup")
}

// AddUserToGroup implements iam.Admin.
func (STSAdmin) AddUserToGroup(_ context.Context, _ resource.AccountID, _, _ string) error {
	return notServed("AddUserToGroup")
}

// RemoveUserFromGroup implements iam.Admin.
func (STSAdmin) RemoveUserFromGroup(_ context.Context, _ resource.AccountID, _, _ string) error {
	return notServed("RemoveUserFromGroup")
}

// ListGroupsForUser implements iam.Admin.
func (STSAdmin) ListGroupsForUser(_ context.Context, _ resource.AccountID, _ string) ([]iam.Group, error) {
	return nil, notServed("ListGroupsForUser")
}

// CreateRole implements iam.Admin.
func (STSAdmin) CreateRole(_ context.Context, _ resource.AccountID, _ iam.RoleInput) (iam.Role, error) {
	return iam.Role{}, notServed("CreateRole")
}

// GetRole implements iam.Admin over RoleService.GetRole. The surface reads
// the role first so a path-scoped role is authorized on its real ARN.
func (a STSAdmin) GetRole(ctx context.Context, account resource.AccountID, name string) (iam.Role, error) {
	role, err := a.role(ctx, account, name)
	if err != nil {
		return iam.Role{}, err
	}
	return roleFromProto(role, name), nil
}

// role fetches one role from vws-iam.
func (a STSAdmin) role(ctx context.Context, account resource.AccountID, name string) (*iamv1.Role, error) {
	role, err := retry(ctx, a.backoff, a.roles.GetRole, &iamv1.GetRoleRequest{Name: roleName(account, name)})
	if err != nil {
		return nil, authError(err)
	}
	return role, nil
}

// roleName is the vws-iam resource name of a role.
func roleName(account resource.AccountID, name string) string {
	return "projects/" + account.String() + "/roles/" + name
}

// UpdateRoleDescription implements iam.Admin over RoleService.UpdateRole with
// a mask on spec.description.
func (a STSAdmin) UpdateRoleDescription(
	ctx context.Context, account resource.AccountID, name, description string,
) (iam.Role, error) {
	if err := iam.ValidateRoleDescription(description); err != nil {
		return iam.Role{}, err
	}
	existing, err := a.role(ctx, account, name)
	if err != nil {
		return iam.Role{}, err
	}
	if iam.IsServiceLinkedRole(existing.GetSpec().GetPath()) {
		return iam.Role{}, iam.UnmodifiableRole(name)
	}
	req := &iamv1.UpdateRoleRequest{
		Role: &iamv1.Role{
			Name: roleName(account, name),
			Spec: &iamv1.RoleSpec{Description: description},
		},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.description"}},
	}
	op, err := call(ctx, a.roles.UpdateRole, req)
	if err != nil {
		return iam.Role{}, authError(err)
	}
	if err := operationResult(op); err != nil {
		return iam.Role{}, err
	}
	resp := op.GetResponse()
	if resp == nil {
		return iam.Role{}, resource.Internal(errors.New("vws-iam UpdateRole returned no role"))
	}
	var role iamv1.Role
	if err := resp.UnmarshalTo(&role); err != nil {
		return iam.Role{}, resource.Internal(fmt.Errorf("decode UpdateRole response: %w", err))
	}
	return roleFromProto(&role, name), nil
}

// roleFromProto maps the fields the IAM Query role shape returns.
func roleFromProto(r *iamv1.Role, name string) iam.Role {
	if n := r.GetName(); n != "" {
		name = n[strings.LastIndex(n, "/")+1:]
	}
	out := iam.Role{
		Name: name, Path: r.GetSpec().GetPath(), ID: r.GetStatus().GetUniqueId(),
		ARN: r.GetStatus().GetArn(), TrustPolicy: r.GetSpec().GetAssumeRolePolicy(),
		Description:        r.GetSpec().GetDescription(),
		MaxSessionDuration: int(r.GetSpec().GetMaxSessionDurationSeconds()),
	}
	if t := r.GetCreateTime(); t != nil {
		out.Created = t.AsTime()
	}
	return out
}

// ListRoles implements iam.Admin.
func (STSAdmin) ListRoles(_ context.Context, _ resource.AccountID, _ string) ([]iam.Role, error) {
	return nil, notServed("ListRoles")
}

// UpdateAssumeRolePolicy implements iam.Admin.
func (STSAdmin) UpdateAssumeRolePolicy(_ context.Context, _ resource.AccountID, _, _ string) error {
	return notServed("UpdateAssumeRolePolicy")
}

// DeleteRole implements iam.Admin.
func (STSAdmin) DeleteRole(_ context.Context, _ resource.AccountID, _ string) error {
	return notServed("DeleteRole")
}

// CreatePolicy implements iam.Admin.
func (STSAdmin) CreatePolicy(_ context.Context, _ resource.AccountID, name, path, _, _ string) (iam.ManagedPolicy, error) {
	return iam.ManagedPolicy{}, notServed("CreatePolicy")
}

// GetPolicy implements iam.Admin.
func (STSAdmin) GetPolicy(_ context.Context, _ resource.AccountID, _ string) (iam.ManagedPolicy, error) {
	return iam.ManagedPolicy{}, notServed("GetPolicy")
}

// ListPolicyVersions implements iam.Admin over
// PolicyService.ListPolicyVersions. The AWS Marker is the proto page token:
// both are opaque to the caller.
func (a STSAdmin) ListPolicyVersions(
	ctx context.Context, account resource.AccountID, arn, marker string, maxItems int,
) (iam.PolicyVersionPage, error) {
	name, err := a.policyFor(ctx, account, arn)
	if err != nil {
		return iam.PolicyVersionPage{}, err
	}
	req := &iamv1.ListPolicyVersionsRequest{Parent: name, PageToken: marker}
	if maxItems > 0 {
		req.PageSize = int32(maxItems) //nolint:gosec // the surface bounds MaxItems to 1..1000.
	}
	resp, err := retry(ctx, a.backoff, a.policies.ListPolicyVersions, req)
	if err != nil {
		return iam.PolicyVersionPage{}, authError(err)
	}
	page := iam.PolicyVersionPage{
		Versions:    []iam.PolicyVersion{},
		IsTruncated: resp.GetNextPageToken() != "",
		Marker:      resp.GetNextPageToken(),
	}
	for _, v := range resp.GetPolicyVersions() {
		page.Versions = append(page.Versions, iam.PolicyVersion{
			ID:               v.GetName()[strings.LastIndex(v.GetName(), "/")+1:],
			IsDefaultVersion: v.GetStatus().GetDefaultVersion(),
			Created:          v.GetCreateTime().AsTime(),
		})
	}
	return page, nil
}

// ListPolicies implements iam.Admin.
func (STSAdmin) ListPolicies(_ context.Context, _ resource.AccountID, _ string) ([]iam.ManagedPolicy, error) {
	return nil, notServed("ListPolicies")
}

// DeletePolicy implements iam.Admin.
func (STSAdmin) DeletePolicy(_ context.Context, _ resource.AccountID, _ string) error {
	return notServed("DeletePolicy")
}

// SetDefaultPolicyVersion implements iam.Admin over PolicyService.UpdatePolicy.
// vws-iam changes spec.default_version and rejects a version it does not store.
func (a STSAdmin) SetDefaultPolicyVersion(
	ctx context.Context, account resource.AccountID, arn, version string,
) error {
	name, err := a.policyFor(ctx, account, arn)
	if err != nil {
		return err
	}
	op, err := call(ctx, a.policies.UpdatePolicy, &iamv1.UpdatePolicyRequest{
		Policy: &iamv1.Policy{Name: name, Spec: &iamv1.PolicySpec{DefaultVersion: version}},
		UpdateMask: &fieldmaskpb.FieldMask{
			Paths: []string{"spec.default_version"},
		},
	})
	if err != nil {
		return authError(err)
	}
	return operationResult(op)
}

// AttachPolicy implements iam.Admin.
func (STSAdmin) AttachPolicy(_ context.Context, _ resource.AccountID, _ iam.Entity, _, _ string) error {
	return notServed("AttachPolicy")
}

// DetachPolicy implements iam.Admin.
func (STSAdmin) DetachPolicy(_ context.Context, _ resource.AccountID, _ iam.Entity, _, _ string) error {
	return notServed("DetachPolicy")
}

// ListAttachedPolicies implements iam.Admin.
func (STSAdmin) ListAttachedPolicies(_ context.Context, _ resource.AccountID, _ iam.Entity, _ string) ([]iam.ManagedPolicy, error) {
	return nil, notServed("ListAttachedPolicies")
}

// PutInlinePolicy implements iam.Admin.
func (STSAdmin) PutInlinePolicy(_ context.Context, _ resource.AccountID, _ iam.Entity, name, _, _ string) error {
	return notServed("PutInlinePolicy")
}

// GetInlinePolicy implements iam.Admin.
func (STSAdmin) GetInlinePolicy(_ context.Context, _ resource.AccountID, _ iam.Entity, _, _ string) (string, error) {
	return "", notServed("GetInlinePolicy")
}

// DeleteInlinePolicy implements iam.Admin.
func (STSAdmin) DeleteInlinePolicy(_ context.Context, _ resource.AccountID, _ iam.Entity, _, _ string) error {
	return notServed("DeleteInlinePolicy")
}

// ListInlinePolicies implements iam.Admin.
func (STSAdmin) ListInlinePolicies(_ context.Context, _ resource.AccountID, _ iam.Entity, _ string) ([]string, error) {
	return nil, notServed("ListInlinePolicies")
}

// CreateLoginProfile implements iam.Admin.
func (STSAdmin) CreateLoginProfile(_ context.Context, _ resource.AccountID, _, _ string) (iam.LoginProfile, error) {
	return iam.LoginProfile{}, notServed("CreateLoginProfile")
}

// GetLoginProfile implements iam.Admin.
func (STSAdmin) GetLoginProfile(_ context.Context, _ resource.AccountID, _ string) (iam.LoginProfile, error) {
	return iam.LoginProfile{}, notServed("GetLoginProfile")
}

// UpdateLoginProfile implements iam.Admin.
func (STSAdmin) UpdateLoginProfile(_ context.Context, _ resource.AccountID, _, _ string) error {
	return notServed("UpdateLoginProfile")
}

// DeleteLoginProfile implements iam.Admin.
func (STSAdmin) DeleteLoginProfile(_ context.Context, _ resource.AccountID, _ string) error {
	return notServed("DeleteLoginProfile")
}

// policyResource turns arn:vws:iam::{project}:policy{path}{name} into
// projects/{project}/policies/{name}. A policy in another account does not
// exist for the caller, as in AWS.
func policyResource(a resource.AccountID, arn string) (string, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" || !strings.HasPrefix(parts[5], "policy") {
		return "", resource.Invalid("policyArn", "not a policy ARN")
	}
	account, err := resource.Parse[resource.AccountID](parts[4])
	if err != nil {
		return "", resource.Invalid("policyArn", "not a policy ARN")
	}
	name := parts[5][strings.LastIndex(parts[5], "/")+1:]
	if name == "" {
		return "", resource.Invalid("policyArn", "not a policy ARN")
	}
	if account != a {
		return "", &resource.Error{
			Code: resource.CodeNotFound, Message: "Policy " + arn + " does not exist or is not attachable.",
		}
	}
	return "projects/" + parts[4] + "/policies/" + name, nil
}

// policyNotFound is the AWS NoSuchEntity answer for a policy the caller may
// not address. It is the same for a missing policy and for an ARN whose path
// does not match the stored policy.
func policyNotFound(arn string) error {
	return &resource.Error{Code: resource.CodeNotFound, Message: "Policy " + arn + " does not exist or is not attachable."}
}

// policyFor resolves a policy ARN to a resource name and checks that the
// stored policy's full ARN, including its path, equals the ARN the caller
// sent. vws-iam addresses a policy by name, and its name does not carry the
// path, so without this check an ARN for one path would reach the policy at
// another path the caller is not authorized on.
func (a STSAdmin) policyFor(ctx context.Context, account resource.AccountID, arn string) (string, error) {
	name, err := policyResource(account, arn)
	if err != nil {
		return "", err
	}
	pol, err := retry(ctx, a.backoff, a.policies.GetPolicy, &iamv1.GetPolicyRequest{Name: name})
	if err != nil {
		if resource.CodeOf(authError(err)) == resource.CodeNotFound {
			return "", policyNotFound(arn)
		}
		return "", authError(err)
	}
	if pol.GetStatus().GetArn() != arn {
		return "", policyNotFound(arn)
	}
	return name, nil
}

// mfaDeviceResource turns arn:vws:iam::{project}:mfa{path}{name} into
// projects/{project}/mfaDevices/{name}. A serial number that names no device
// of the caller, as in AWS, does not exist.
func mfaDeviceResource(a resource.AccountID, serial string) (string, error) {
	parts := strings.SplitN(serial, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" {
		return "", mfaDeviceNotFound()
	}
	account, err := resource.Parse[resource.AccountID](parts[4])
	if err != nil {
		return "", mfaDeviceNotFound()
	}
	rest, ok := strings.CutPrefix(parts[5], "mfa/")
	if !ok || rest == "" || account != a {
		return "", mfaDeviceNotFound()
	}
	name := rest[strings.LastIndex(rest, "/")+1:]
	if name == "" {
		return "", mfaDeviceNotFound()
	}
	return "projects/" + parts[4] + "/mfaDevices/" + name, nil
}

func mfaDeviceNotFound() error {
	return &resource.Error{Code: resource.CodeNotFound, Message: "The specified MFA device does not exist."}
}

// mfaDeviceFor resolves a device serial number to a resource name and checks
// that the stored serial number, including its partition, region, account,
// path and name, equals the serial number the caller sent. vws-iam addresses a
// device by the name in the resource, not by its full serial number, so
// without this check a serial number for one partition, region or path would
// reach the same device. The answer for a mismatch is the answer for a missing
// device.
func (a STSAdmin) mfaDeviceFor(ctx context.Context, account resource.AccountID, serial string) (string, error) {
	name, err := mfaDeviceResource(account, serial)
	if err != nil {
		return "", err
	}
	dev, err := retry(ctx, a.backoff, a.mfaDevices.GetMfaDevice, &iamv1.GetMfaDeviceRequest{Name: name})
	if err != nil {
		if resource.CodeOf(authError(err)) == resource.CodeNotFound {
			return "", mfaDeviceNotFound()
		}
		return "", authError(err)
	}
	if dev.GetStatus().GetSerialNumber() != serial {
		return "", mfaDeviceNotFound()
	}
	return name, nil
}

// operationResult maps a finished vws-iam operation to an error. vws-iam
// answers IAM mutations synchronously, so a running operation is a fault.
func operationResult(op *longrunningpb.Operation) error {
	switch {
	case op == nil:
		return resource.Internal(errors.New("vws-iam returned no operation"))
	case !op.GetDone():
		return resource.Internal(errors.New("vws-iam returned a running operation"))
	case op.GetError() != nil:
		return authError(status.ErrorProto(op.GetError()))
	}
	return nil
}

// TagPolicy implements iam.Admin over PolicyService.TagPolicy.
func (a STSAdmin) TagPolicy(ctx context.Context, account resource.AccountID, arn string, tags []iam.Tag) error {
	name, err := a.policyFor(ctx, account, arn)
	if err != nil {
		return err
	}
	req := &iamv1.TagPolicyRequest{Name: name, Tags: make([]*iamv1.Tag, 0, len(tags))}
	for _, tag := range tags {
		req.Tags = append(req.Tags, &iamv1.Tag{Key: tag.Key, Value: tag.Value})
	}
	op, err := call(ctx, a.policies.TagPolicy, req)
	if err != nil {
		return authError(err)
	}
	return operationResult(op)
}

// UntagPolicy implements iam.Admin over PolicyService.UntagPolicy.
func (a STSAdmin) UntagPolicy(ctx context.Context, account resource.AccountID, arn string, keys []string) error {
	name, err := a.policyFor(ctx, account, arn)
	if err != nil {
		return err
	}
	op, err := call(ctx, a.policies.UntagPolicy, &iamv1.UntagPolicyRequest{Name: name, TagKeys: keys})
	if err != nil {
		return authError(err)
	}
	return operationResult(op)
}

// ListPolicyTags implements iam.Admin over PolicyService.ListPolicyTags. The
// AWS Marker is the proto page token: both are opaque to the caller.
func (a STSAdmin) ListPolicyTags(
	ctx context.Context, account resource.AccountID, arn, marker string, maxItems int,
) (iam.TagPage, error) {
	name, err := a.policyFor(ctx, account, arn)
	if err != nil {
		return iam.TagPage{}, err
	}
	req := &iamv1.ListPolicyTagsRequest{Name: name, PageToken: marker}
	if maxItems > 0 {
		req.PageSize = int32(maxItems) //nolint:gosec // the surface bounds MaxItems to 1..1000.
	}
	resp, err := retry(ctx, a.backoff, a.policies.ListPolicyTags, req)
	if err != nil {
		return iam.TagPage{}, authError(err)
	}
	page := iam.TagPage{Tags: []iam.Tag{}, IsTruncated: resp.GetNextPageToken() != "", Marker: resp.GetNextPageToken()}
	for _, tag := range resp.GetTags() {
		page.Tags = append(page.Tags, iam.Tag{Key: tag.GetKey(), Value: tag.GetValue()})
	}
	return page, nil
}

// TagMFADevice implements iam.Admin over MfaDeviceService.TagMFADevice.
func (a STSAdmin) TagMFADevice(ctx context.Context, account resource.AccountID, serial string, tags []iam.Tag) error {
	name, err := a.mfaDeviceFor(ctx, account, serial)
	if err != nil {
		return err
	}
	req := &iamv1.TagMFADeviceRequest{Name: name, Tags: make([]*iamv1.Tag, 0, len(tags))}
	for _, tag := range tags {
		req.Tags = append(req.Tags, &iamv1.Tag{Key: tag.Key, Value: tag.Value})
	}
	op, err := call(ctx, a.mfaDevices.TagMFADevice, req)
	if err != nil {
		return authError(err)
	}
	return operationResult(op)
}

// UntagMFADevice implements iam.Admin over MfaDeviceService.UntagMFADevice.
func (a STSAdmin) UntagMFADevice(ctx context.Context, account resource.AccountID, serial string, keys []string) error {
	name, err := a.mfaDeviceFor(ctx, account, serial)
	if err != nil {
		return err
	}
	op, err := call(ctx, a.mfaDevices.UntagMFADevice, &iamv1.UntagMFADeviceRequest{Name: name, TagKeys: keys})
	if err != nil {
		return authError(err)
	}
	return operationResult(op)
}

// ListMFADeviceTags implements iam.Admin over MfaDeviceService.ListMFADeviceTags.
// The AWS Marker is the proto page token: both are opaque to the caller.
func (a STSAdmin) ListMFADeviceTags(
	ctx context.Context, account resource.AccountID, serial, marker string, maxItems int,
) (iam.TagPage, error) {
	name, err := a.mfaDeviceFor(ctx, account, serial)
	if err != nil {
		return iam.TagPage{}, err
	}
	req := &iamv1.ListMFADeviceTagsRequest{Name: name, PageToken: marker}
	if maxItems > 0 {
		req.PageSize = int32(maxItems) //nolint:gosec // the surface bounds MaxItems to 1..1000.
	}
	resp, err := retry(ctx, a.backoff, a.mfaDevices.ListMFADeviceTags, req)
	if err != nil {
		return iam.TagPage{}, authError(err)
	}
	page := iam.TagPage{Tags: []iam.Tag{}, IsTruncated: resp.GetNextPageToken() != "", Marker: resp.GetNextPageToken()}
	for _, tag := range resp.GetTags() {
		page.Tags = append(page.Tags, iam.Tag{Key: tag.GetKey(), Value: tag.GetValue()})
	}
	return page, nil
}
