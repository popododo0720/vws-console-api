package iamclient

import (
	"context"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// STSAdmin serves the IAM Query surface's STS calls over vws-iam. The IAM
// management calls are not mapped to vws-iam's User, Group, Role, Policy and
// AccessKey services yet; each answers Unimplemented, which the surface
// returns as InvalidAction.
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

// GetRole implements iam.Admin.
func (STSAdmin) GetRole(_ context.Context, _ resource.AccountID, _ string) (iam.Role, error) {
	return iam.Role{}, notServed("GetRole")
}

// ListRoles implements iam.Admin.
func (STSAdmin) ListRoles(_ context.Context, _ resource.AccountID, _ string) ([]iam.Role, error) {
	return nil, notServed("ListRoles")
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

// ListPolicies implements iam.Admin.
func (STSAdmin) ListPolicies(_ context.Context, _ resource.AccountID, _ string) ([]iam.ManagedPolicy, error) {
	return nil, notServed("ListPolicies")
}

// DeletePolicy implements iam.Admin.
func (STSAdmin) DeletePolicy(_ context.Context, _ resource.AccountID, _ string) error {
	return notServed("DeletePolicy")
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
