package iam

import (
	"context"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Entity is the kind of identity a policy attaches to.
type Entity int

// The three policy holders.
const (
	EntityUser Entity = iota + 1
	EntityGroup
	EntityRole
)

// String returns the IAM word for the entity.
func (e Entity) String() string {
	switch e {
	case EntityUser:
		return "user"
	case EntityGroup:
		return "group"
	case EntityRole:
		return "role"
	default:
		return ""
	}
}

// User is an IAM user.
type User struct {
	Name, Path, ID, ARN string
	Created             time.Time
}

// Group is an IAM group.
type Group struct {
	Name, Path, ID, ARN string
	Created             time.Time
}

// RoleInput is what CreateRole takes.
type RoleInput struct {
	Name, Path, TrustPolicy, Description string
	// MaxSessionDuration in seconds, 3600 to 43200. Zero means 3600.
	MaxSessionDuration int
}

// Role is an IAM role.
type Role struct {
	Name, Path, ID, ARN, TrustPolicy, Description string
	MaxSessionDuration                            int
	Created                                       time.Time
}

// ManagedPolicy is a customer managed policy. Only version v1 exists.
type ManagedPolicy struct {
	Name, Path, ID, ARN, Description, Document string
	AttachmentCount                            int
	Created, Updated                           time.Time
}

// AccessKeyMeta is an access key without its secret.
type AccessKeyMeta struct {
	UserName, AccessKeyID, Status string
	Created                       time.Time
}

// NewAccessKey is returned once, at creation, with the secret.
type NewAccessKey struct {
	AccessKeyMeta
	Secret string
}

// AssumedRole is the result of AssumeRole.
type AssumedRole struct {
	Key           Key
	AssumedRoleID string // role id ":" session name
	ARN           string // arn:vws:sts::<account>:assumed-role/<role>/<session>
}

// Admin is the IAM management API behind the IAM and STS Query surface. Every
// call is scoped to one account. Errors are *resource.Error: NotFound,
// AlreadyExists, Conflict (delete conflict), InvalidArgument (Field
// "PolicyDocument" for a malformed policy), ResourceExhausted (a quota),
// PermissionDenied (AssumeRole trust).
type Admin interface {
	CreateUser(ctx context.Context, a resource.AccountID, name, path string) (User, error)
	GetUser(ctx context.Context, a resource.AccountID, name string) (User, error)
	ListUsers(ctx context.Context, a resource.AccountID, pathPrefix string) ([]User, error)
	DeleteUser(ctx context.Context, a resource.AccountID, name string) error

	CreateLoginProfile(ctx context.Context, a resource.AccountID, user, password string) (LoginProfile, error)
	GetLoginProfile(ctx context.Context, a resource.AccountID, user string) (LoginProfile, error)
	UpdateLoginProfile(ctx context.Context, a resource.AccountID, user, password string) error
	DeleteLoginProfile(ctx context.Context, a resource.AccountID, user string) error

	CreateAccessKey(ctx context.Context, a resource.AccountID, user string) (NewAccessKey, error)
	ListAccessKeys(ctx context.Context, a resource.AccountID, user string) ([]AccessKeyMeta, error)
	DeleteAccessKey(ctx context.Context, a resource.AccountID, user, keyID string) error

	CreateGroup(ctx context.Context, a resource.AccountID, name, path string) (Group, error)
	GetGroup(ctx context.Context, a resource.AccountID, name string) (Group, []User, error)
	ListGroups(ctx context.Context, a resource.AccountID, pathPrefix string) ([]Group, error)
	DeleteGroup(ctx context.Context, a resource.AccountID, name string) error
	AddUserToGroup(ctx context.Context, a resource.AccountID, group, user string) error
	RemoveUserFromGroup(ctx context.Context, a resource.AccountID, group, user string) error
	ListGroupsForUser(ctx context.Context, a resource.AccountID, user string) ([]Group, error)

	CreateRole(ctx context.Context, a resource.AccountID, in RoleInput) (Role, error)
	GetRole(ctx context.Context, a resource.AccountID, name string) (Role, error)
	ListRoles(ctx context.Context, a resource.AccountID, pathPrefix string) ([]Role, error)
	UpdateAssumeRolePolicy(ctx context.Context, a resource.AccountID, name, document string) error
	DeleteRole(ctx context.Context, a resource.AccountID, name string) error

	CreatePolicy(ctx context.Context, a resource.AccountID, name, path, document, description string) (ManagedPolicy, error)
	GetPolicy(ctx context.Context, a resource.AccountID, arn string) (ManagedPolicy, error)
	ListPolicies(ctx context.Context, a resource.AccountID, pathPrefix string) ([]ManagedPolicy, error)
	DeletePolicy(ctx context.Context, a resource.AccountID, arn string) error
	AttachPolicy(ctx context.Context, a resource.AccountID, kind Entity, name, arn string) error
	DetachPolicy(ctx context.Context, a resource.AccountID, kind Entity, name, arn string) error
	ListAttachedPolicies(ctx context.Context, a resource.AccountID, kind Entity, name string) ([]ManagedPolicy, error)

	PutInlinePolicy(ctx context.Context, a resource.AccountID, kind Entity, name, policy, document string) error
	GetInlinePolicy(ctx context.Context, a resource.AccountID, kind Entity, name, policy string) (string, error)
	DeleteInlinePolicy(ctx context.Context, a resource.AccountID, kind Entity, name, policy string) error
	ListInlinePolicies(ctx context.Context, a resource.AccountID, kind Entity, name string) ([]string, error)

	TagPolicy(ctx context.Context, a resource.AccountID, arn string, tags []Tag) error
	UntagPolicy(ctx context.Context, a resource.AccountID, arn string, keys []string) error
	ListPolicyTags(ctx context.Context, a resource.AccountID, arn, marker string, maxItems int) (TagPage, error)

	// The MFA device argument is the device serial number, the ARN the AWS
	// Query API calls SerialNumber.
	TagMFADevice(ctx context.Context, a resource.AccountID, serial string, tags []Tag) error
	UntagMFADevice(ctx context.Context, a resource.AccountID, serial string, keys []string) error
	ListMFADeviceTags(ctx context.Context, a resource.AccountID, serial, marker string, maxItems int) (TagPage, error)

	AssumeRole(ctx context.Context, caller Principal, roleARN, session string, duration time.Duration) (AssumedRole, error)
}

// LoginProfile is a user's console password. The password itself is never
// returned.
type LoginProfile struct {
	UserName string
	Created  time.Time
}
