package iamclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// STSAdmin serves the IAM Query surface's STS calls over vws-iam. The user
// and group calls are mapped to UserService and GroupService (see
// users_groups.go), except a rename, which vws-iam cannot do. The other IAM
// management calls are not mapped to vws-iam's Role, Policy and AccessKey
// services yet; each answers Unimplemented, which the surface returns as
// InvalidAction. CreatePolicyVersion, GetPolicyVersion,
// ListPolicyVersions, SetDefaultPolicyVersion, DeletePolicyVersion, the policy
// and MFA device tag calls, ListVirtualMFADevices, GetRole, UpdateRole,
// UpdateRoleDescription and GetAccessKeyLastUsed are mapped. GetMFADevice
// answers NoSuchEntity without a call (see GetMFADevice).
type STSAdmin struct{ *Client }

var _ iam.Admin = STSAdmin{}

func notServed(op string) error {
	return resource.Unimplemented(op + " is not served over vws-iam gRPC yet")
}

// CreateAccessKey implements iam.Admin.
func (STSAdmin) CreateAccessKey(_ context.Context, _ resource.AccountID, _ string) (iam.NewAccessKey, error) {
	return iam.NewAccessKey{}, notServed("CreateAccessKey")
}

// ListAccessKeys implements iam.Admin.
func (STSAdmin) ListAccessKeys(_ context.Context, _ resource.AccountID, _ string) ([]iam.AccessKeyMeta, error) {
	return nil, notServed("ListAccessKeys")
}

// GetAccessKeyLastUsed implements iam.Admin over
// AccessKeyService.GetAccessKey. vws-iam addresses a key by its owning user,
// so the call reads the key under each user of the account until one holds
// it. The key id is globally unique. The proto has no lookup by key id, so
// this is one read per user.
func (a STSAdmin) GetAccessKeyLastUsed(
	ctx context.Context, account resource.AccountID, keyID string,
) (iam.AccessKeyLastUsed, error) {
	ctx, cancel := context.WithTimeout(ctx, accessKeyScanTimeout)
	defer cancel()
	parent := "projects/" + account.String()
	var token string
	for {
		page, err := retry(ctx, a.backoff, a.users.ListUsers, &iamv1.ListUsersRequest{
			Parent: parent, PageSize: 100, PageToken: token,
		})
		if err != nil {
			return iam.AccessKeyLastUsed{}, authError(err)
		}
		for _, u := range page.GetUsers() {
			want := u.GetName() + "/accessKeys/" + keyID
			key, err := retry(ctx, a.backoff, a.accessKeys.GetAccessKey, &iamv1.GetAccessKeyRequest{Name: want})
			if err != nil {
				mapped := authError(err)
				if resource.CodeOf(mapped) == resource.CodeNotFound {
					continue
				}
				return iam.AccessKeyLastUsed{}, mapped
			}
			if key.GetName() != want {
				return iam.AccessKeyLastUsed{}, resource.Internal(
					errors.New("vws-iam GetAccessKey returned " + key.GetName() + ", want " + want))
			}
			return lastUsedOf(key, u)
		}
		token = page.GetNextPageToken()
		if token == "" {
			return iam.AccessKeyLastUsed{}, iam.AccessKeyNotFound(keyID)
		}
	}
}

// accessKeyScanTimeout bounds the user scan, which is one read per user.
const accessKeyScanTimeout = 10 * time.Second

// lastUsedOf maps a vws-iam key and its owner to the IAM Query answer.
func lastUsedOf(key *iamv1.AccessKey, user *iamv1.User) (iam.AccessKeyLastUsed, error) {
	arn := user.GetStatus().GetArn()
	if arn == "" {
		return iam.AccessKeyLastUsed{}, resource.Internal(
			errors.New("vws-iam access key has no owning user ARN"))
	}
	name := user.GetName()
	out := iam.AccessKeyLastUsed{
		UserName: name[strings.LastIndex(name, "/")+1:],
		UserARN:  arn,
		Service:  key.GetStatus().GetLastUsedService(),
		Region:   key.GetStatus().GetLastUsedRegion(),
	}
	if t := key.GetStatus().GetLastUsedTime(); t != nil {
		out.LastUsed = t.AsTime()
	}
	return out, nil
}

// DeleteAccessKey implements iam.Admin.
func (STSAdmin) DeleteAccessKey(_ context.Context, _ resource.AccountID, _, _ string) error {
	return notServed("DeleteAccessKey")
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

// UpdateRole implements iam.Admin over RoleService.UpdateRole with a mask on
// the fields the caller set.
func (a STSAdmin) UpdateRole(
	ctx context.Context, account resource.AccountID, name string, in iam.RoleUpdate,
) error {
	if in.Description != nil {
		if err := iam.ValidateRoleDescription(*in.Description); err != nil {
			return err
		}
	}
	if in.MaxSessionDuration != nil {
		if err := iam.ValidateMaxSessionDuration(*in.MaxSessionDuration); err != nil {
			return err
		}
	}
	existing, err := a.role(ctx, account, name)
	if err != nil {
		return err
	}
	if iam.IsServiceLinkedRole(existing.GetSpec().GetPath()) {
		return iam.UnmodifiableRole(name)
	}
	if in.Description == nil && in.MaxSessionDuration == nil {
		return nil
	}
	spec := &iamv1.RoleSpec{}
	paths := make([]string, 0, 2)
	if in.Description != nil {
		spec.Description = *in.Description
		paths = append(paths, "spec.description")
	}
	if in.MaxSessionDuration != nil {
		spec.MaxSessionDurationSeconds = int32(*in.MaxSessionDuration)
		paths = append(paths, "spec.max_session_duration_seconds")
	}
	req := &iamv1.UpdateRoleRequest{
		Role:       &iamv1.Role{Name: roleName(account, name), Spec: spec},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: paths},
	}
	op, err := call(ctx, a.roles.UpdateRole, req)
	if err != nil {
		return authError(err)
	}
	return operationResult(op)
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

// CreatePolicyVersion implements iam.Admin over
// PolicyService.CreatePolicyVersion. The version id and default flag come
// from the stored policy, as AWS assigns v<n> in order.
func (a STSAdmin) CreatePolicyVersion(
	ctx context.Context, account resource.AccountID, arn, document string, setAsDefault bool,
) (iam.PolicyVersion, error) {
	name, err := a.policyFor(ctx, account, arn)
	if err != nil {
		return iam.PolicyVersion{}, err
	}
	op, err := call(ctx, a.policies.CreatePolicyVersion, &iamv1.CreatePolicyVersionRequest{
		Parent: name,
		PolicyVersion: &iamv1.PolicyVersion{
			Spec: &iamv1.PolicyVersionSpec{Document: document, SetAsDefault: setAsDefault},
		},
	})
	if err != nil {
		return iam.PolicyVersion{}, authError(err)
	}
	if err := operationResult(op); err != nil {
		return iam.PolicyVersion{}, err
	}
	resp := op.GetResponse()
	if resp == nil {
		return iam.PolicyVersion{}, resource.Internal(errors.New("vws-iam CreatePolicyVersion returned no version"))
	}
	var created iamv1.PolicyVersion
	if err := resp.UnmarshalTo(&created); err != nil {
		return iam.PolicyVersion{}, resource.Internal(fmt.Errorf("decode CreatePolicyVersion response: %w", err))
	}
	out := iam.PolicyVersion{
		ID:               created.GetName()[strings.LastIndex(created.GetName(), "/")+1:],
		IsDefaultVersion: created.GetStatus().GetDefaultVersion(),
	}
	if t := created.GetCreateTime(); t != nil {
		out.Created = t.AsTime()
	}
	return out, nil
}

// GetPolicyVersion implements iam.Admin over PolicyService.GetPolicyVersion.
func (a STSAdmin) GetPolicyVersion(
	ctx context.Context, account resource.AccountID, arn, versionID string,
) (iam.PolicyVersion, error) {
	name, err := a.policyFor(ctx, account, arn)
	if err != nil {
		return iam.PolicyVersion{}, err
	}
	v, err := retry(ctx, a.backoff, a.policies.GetPolicyVersion, &iamv1.GetPolicyVersionRequest{
		Name: name + "/versions/" + versionID,
	})
	if err != nil {
		return iam.PolicyVersion{}, authError(err)
	}
	out := iam.PolicyVersion{
		ID:               v.GetName()[strings.LastIndex(v.GetName(), "/")+1:],
		Document:         v.GetSpec().GetDocument(),
		IsDefaultVersion: v.GetStatus().GetDefaultVersion(),
	}
	if t := v.GetCreateTime(); t != nil {
		out.Created = t.AsTime()
	}
	return out, nil
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

// DeletePolicyVersion implements iam.Admin over
// PolicyService.DeletePolicyVersion.
func (a STSAdmin) DeletePolicyVersion(
	ctx context.Context, account resource.AccountID, arn, versionID string,
) error {
	name, err := a.policyFor(ctx, account, arn)
	if err != nil {
		return err
	}
	op, err := call(ctx, a.policies.DeletePolicyVersion, &iamv1.DeletePolicyVersionRequest{
		Name: name + "/versions/" + versionID,
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
		return "", iam.MFADeviceNotFound()
	}
	account, err := resource.Parse[resource.AccountID](parts[4])
	if err != nil {
		return "", iam.MFADeviceNotFound()
	}
	rest, ok := strings.CutPrefix(parts[5], "mfa/")
	if !ok || rest == "" || account != a {
		return "", iam.MFADeviceNotFound()
	}
	name := rest[strings.LastIndex(rest, "/")+1:]
	if name == "" {
		return "", iam.MFADeviceNotFound()
	}
	return "projects/" + parts[4] + "/mfaDevices/" + name, nil
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
			return "", iam.MFADeviceNotFound()
		}
		return "", authError(err)
	}
	if dev.GetStatus().GetSerialNumber() != serial {
		return "", iam.MFADeviceNotFound()
	}
	return name, nil
}

// GetMFADevice implements iam.Admin. AWS GetMFADevice accepts only FIDO
// security key serial numbers (u2f/), and vws-iam keeps no FIDO keys
// (popododo0720/vws-iam#133), so every serial number, a virtual mfa/ device
// included, is a device the account does not hold. vws-iam is not called:
// MfaDeviceService.GetMfaDevice reads virtual devices, which this action does
// not serve.
func (STSAdmin) GetMFADevice(context.Context, resource.AccountID, string) (iam.MFADevice, error) {
	return iam.MFADevice{}, iam.MFADeviceNotFound()
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

// ListVirtualMFADevices implements iam.Admin over
// MfaDeviceService.ListMfaDevices. vws-iam pages every device before the
// assignment filter, so this reads every page and then filters and pages to
// keep AWS's MaxItems and Marker semantics.
func (a STSAdmin) ListVirtualMFADevices(
	ctx context.Context, account resource.AccountID, assignment iam.MFADeviceAssignment, marker string, maxItems int,
) (iam.VirtualMFADevicePage, error) {
	var devices []iam.VirtualMFADevice
	token := ""
	for {
		resp, err := retry(ctx, a.backoff, a.mfaDevices.ListMfaDevices, &iamv1.ListMfaDevicesRequest{
			Parent: "projects/" + account.String(), PageSize: iam.MaxMFADevicePageSize, PageToken: token,
		})
		if err != nil {
			return iam.VirtualMFADevicePage{}, authError(err)
		}
		for _, dev := range resp.GetMfaDevices() {
			if !assignment.Matches(dev.GetStatus().GetUser() != "") {
				continue
			}
			v, err := a.virtualMFADevice(ctx, account, dev)
			if err != nil {
				return iam.VirtualMFADevicePage{}, err
			}
			devices = append(devices, v)
		}
		token = resp.GetNextPageToken()
		if token == "" {
			return iam.PageVirtualMFADevices(devices, assignment, marker, maxItems), nil
		}
	}
}

// virtualMFADevice maps one vws-iam device to an AWS row. A device with a user
// is assigned, and that user is read for the full AWS User structure. A device
// or user that names another account is an internal error.
func (a STSAdmin) virtualMFADevice(
	ctx context.Context, account resource.AccountID, dev *iamv1.MfaDevice,
) (iam.VirtualMFADevice, error) {
	status := dev.GetStatus()
	serial := status.GetSerialNumber()
	if serial == "" {
		return iam.VirtualMFADevice{}, resource.Internal(
			errors.New("vws-iam ListMfaDevices returned a device with no serial number"))
	}
	if _, err := mfaDeviceResource(account, serial); err != nil {
		return iam.VirtualMFADevice{}, resource.Internal(
			errors.New("vws-iam ListMfaDevices returned a device outside the caller's account"))
	}
	out := iam.VirtualMFADevice{SerialNumber: serial}
	if status.GetUser() == "" {
		return out, nil
	}
	if !userResourceInAccount(account, status.GetUser()) {
		return iam.VirtualMFADevice{}, resource.Internal(
			errors.New("vws-iam ListMfaDevices returned a user outside the caller's account"))
	}
	user, err := a.userFor(ctx, account, status.GetUser())
	if err != nil {
		return iam.VirtualMFADevice{}, err
	}
	out.User = &user
	if t := status.GetEnableTime(); t != nil {
		out.EnableDate = t.AsTime()
	}
	return out, nil
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
