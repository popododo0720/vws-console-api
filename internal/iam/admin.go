package iam

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

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

// RoleUpdate is what UpdateRole changes. A nil field keeps the stored value.
type RoleUpdate struct {
	Description        *string
	MaxSessionDuration *int
}

// MaxRoleDescription is AWS's limit on a role description.
const MaxRoleDescription = 1000

// ServiceLinkedRolePath is the path AWS reserves for service-linked roles.
const ServiceLinkedRolePath = "/aws-service-role/"

// ValidateRoleDescription reports a description AWS rejects: longer than 1000
// characters, or outside the documented character set.
func ValidateRoleDescription(description string) error {
	if utf8.RuneCountInString(description) > MaxRoleDescription {
		return resource.Invalid("description",
			"1 validation error detected: Value at 'description' failed to satisfy constraint: "+
				"Member must have length less than or equal to 1000")
	}
	for _, r := range description {
		if r == '\t' || r == '\n' || r == '\r' ||
			(r >= '\u0020' && r <= '\u007e') || (r >= '\u00a1' && r <= '\u00ff') {
			continue
		}
		return resource.Invalid("description",
			"1 validation error detected: Value at 'description' failed to satisfy constraint: "+
				`Member must satisfy regular expression pattern: [\u0009\u000A\u000D\u0020-\u007E\u00A1-\u00FF]*`)
	}
	return nil
}

// ValidateMaxSessionDuration reports a value outside the AWS range.
func ValidateMaxSessionDuration(seconds int) error {
	if seconds < defaultMaxSession || seconds > maxMaxSession {
		return resource.Invalid("maxSessionDuration", "MaxSessionDuration must be between 3600 and 43200 seconds")
	}
	return nil
}

// IsServiceLinkedRole reports a path only the service that owns the role may
// change.
func IsServiceLinkedRole(path string) bool {
	return strings.HasPrefix(path, ServiceLinkedRolePath)
}

// UnmodifiableRole reports a service-linked role as AWS UnmodifiableEntity.
func UnmodifiableRole(name string) error {
	return &resource.Error{
		Code: resource.CodeConflict, Field: "UnmodifiableEntity",
		Message: "The role " + name + " is a service-linked role and only the service that depends on it can modify it.",
	}
}

// Role is an IAM role.
type Role struct {
	Name, Path, ID, ARN, TrustPolicy, Description string
	MaxSessionDuration                            int
	Created                                       time.Time
}

// ManagedPolicy is a customer managed policy. Its document lives with the
// policy's versions.
type ManagedPolicy struct {
	Name, Path, ID, ARN, Description string
	DefaultVersion                   string
	AttachmentCount                  int
	Created, Updated                 time.Time
}

// PolicyVersion is one version of a managed policy. Document is the raw
// policy JSON.
type PolicyVersion struct {
	ID               string
	Document         string
	IsDefaultVersion bool
	Created          time.Time
}

// PolicyVersionPage is one page of ListPolicyVersions. Marker is the value the
// next call sends as Marker; it is empty on the last page.
type PolicyVersionPage struct {
	Versions    []PolicyVersion
	IsTruncated bool
	Marker      string
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

// AccessKeyLastUsed is when and where an access key was last used. Service
// and Region are empty when the key has never been used. UserARN is the
// owning user's real ARN, for authorization.
type AccessKeyLastUsed struct {
	UserName, UserARN string
	LastUsed          time.Time
	Service, Region   string
}

// AccessKeyNotFound is the NoSuchEntity answer for an access key the account
// does not hold.
func AccessKeyNotFound(keyID string) error {
	return &resource.Error{
		Code: resource.CodeNotFound, Message: "The access key with id " + keyID + " cannot be found.",
	}
}

// MFADevice is an MFA device as GetMFADevice and ListMFADevices report it.
// GetMFADevice accepts only FIDO security keys, and no backend holds FIDO keys
// yet (popododo0720/vws-iam#133), so GetMFADevice answers NoSuchEntity for
// every serial number. ListMFADevices reports the virtual devices enabled for
// one user.
type MFADevice struct {
	UserName     string
	SerialNumber string
	Enabled      time.Time
}

// MFADeviceNotFound is the NoSuchEntity answer for a device the account does
// not hold.
func MFADeviceNotFound() error {
	return &resource.Error{Code: resource.CodeNotFound, Message: "The specified MFA device does not exist."}
}

// AssumedRole is the result of AssumeRole.
type AssumedRole struct {
	Key           Key
	AssumedRoleID string // role id ":" session name
	ARN           string // arn:vws:sts::<account>:assumed-role/<role>/<session>
}

// Ref is the identity of one IAM user, group or role: its ARN, path
// included, and its unique ID.
type Ref struct{ ARN, ID string }

// Resolver reads the identity of a named user, group or role before any
// authorization decision. AWS authorizes an IAM request on the resource's
// ARN, and that ARN includes the entity's path, which the request does not
// carry (the resource types table of
// https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsidentityandaccessmanagementiam.html),
// so the surface reads it by name first. A Resolver answers that identity
// only, never the entity's data: every read of a named entity's data is an
// Admin call bound to the AuthorizedARN the caller was then authorized on
// (#342, #358). GetCallerIdentity also resolves the caller's own unique ID,
// which AWS answers with no permission at all
// (https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html).
// A missing entity is NotFound with the AWS NoSuchEntity message.
type Resolver interface {
	ResolveUser(ctx context.Context, a resource.AccountID, name string) (Ref, error)
	ResolveGroup(ctx context.Context, a resource.AccountID, name string) (Ref, error)
	ResolveRole(ctx context.Context, a resource.AccountID, name string) (Ref, error)
}

// Directory is the IAM backend the Query surface wires: the bound Admin
// calls and the Resolver lookups it authorizes on.
type Directory interface {
	Admin
	Resolver
}

// Admin is the IAM management API behind the IAM and STS Query surface. Every
// call is scoped to one account. Every call that acts on a named user, group
// or role after authorization takes the AuthorizedARN the caller was
// authorized on (#342): the zero value is Unbound (internal) before anything
// is read, and an entity whose ARN is no longer the authorized one is a
// ConcurrentModification (Changed) with no data and no write. The Create
// calls take none: they name an entity that does not exist yet. The lookup
// the surface authorizes on is Resolver, not Admin (#358). Errors are
// *resource.Error: NotFound,
// AlreadyExists, Conflict (delete conflict, Field "UnmodifiableEntity" for a
// service-linked role, or Field ConcurrentModification for an entity that
// moved since authorization), InvalidArgument (Field "PolicyDocument" for a
// malformed policy), ResourceExhausted (a quota), PermissionDenied (AssumeRole
// trust).
type Admin interface {
	CreateUser(ctx context.Context, a resource.AccountID, name, path string) (User, error)
	GetUser(ctx context.Context, a resource.AccountID, name string, want AuthorizedARN) (User, error)
	ListUsers(ctx context.Context, a resource.AccountID, pathPrefix string) ([]User, error)
	DeleteUser(ctx context.Context, a resource.AccountID, name string, want AuthorizedARN) error
	// UpdateUser moves a user's path or name.
	UpdateUser(ctx context.Context, a resource.AccountID, name, newPath, newName string, want AuthorizedARN) error

	CreateLoginProfile(
		ctx context.Context, a resource.AccountID, user, password string, want AuthorizedARN,
	) (LoginProfile, error)
	GetLoginProfile(ctx context.Context, a resource.AccountID, user string, want AuthorizedARN) (LoginProfile, error)
	UpdateLoginProfile(ctx context.Context, a resource.AccountID, user, password string, want AuthorizedARN) error
	DeleteLoginProfile(ctx context.Context, a resource.AccountID, user string, want AuthorizedARN) error

	// The access key secret is only ever in the CreateAccessKey result.
	CreateAccessKey(ctx context.Context, a resource.AccountID, user string, want AuthorizedARN) (NewAccessKey, error)
	ListAccessKeys(ctx context.Context, a resource.AccountID, user string, want AuthorizedARN) ([]AccessKeyMeta, error)
	GetAccessKeyLastUsed(ctx context.Context, a resource.AccountID, keyID string) (AccessKeyLastUsed, error)
	DeleteAccessKey(ctx context.Context, a resource.AccountID, user, keyID string, want AuthorizedARN) error

	CreateGroup(ctx context.Context, a resource.AccountID, name, path string) (Group, error)
	GetGroup(ctx context.Context, a resource.AccountID, name string, want AuthorizedARN) (Group, []User, error)
	ListGroups(ctx context.Context, a resource.AccountID, pathPrefix string) ([]Group, error)
	// UpdateGroup, DeleteGroup, AddUserToGroup and RemoveUserFromGroup are
	// bound to the group's ARN; ListGroupsForUser to the user's.
	UpdateGroup(ctx context.Context, a resource.AccountID, name, newPath, newName string, want AuthorizedARN) error
	DeleteGroup(ctx context.Context, a resource.AccountID, name string, want AuthorizedARN) error
	AddUserToGroup(ctx context.Context, a resource.AccountID, group, user string, want AuthorizedARN) error
	RemoveUserFromGroup(ctx context.Context, a resource.AccountID, group, user string, want AuthorizedARN) error
	ListGroupsForUser(ctx context.Context, a resource.AccountID, user string, want AuthorizedARN) ([]Group, error)

	CreateRole(ctx context.Context, a resource.AccountID, in RoleInput) (Role, error)
	GetRole(ctx context.Context, a resource.AccountID, name string, want AuthorizedARN) (Role, error)
	UpdateRole(ctx context.Context, a resource.AccountID, name string, in RoleUpdate, want AuthorizedARN) error
	UpdateRoleDescription(
		ctx context.Context, a resource.AccountID, name, description string, want AuthorizedARN,
	) (Role, error)
	ListRoles(ctx context.Context, a resource.AccountID, pathPrefix string) ([]Role, error)
	UpdateAssumeRolePolicy(ctx context.Context, a resource.AccountID, name, document string, want AuthorizedARN) error
	DeleteRole(ctx context.Context, a resource.AccountID, name string, want AuthorizedARN) error

	CreatePolicy(ctx context.Context, a resource.AccountID, name, path, document, description string) (ManagedPolicy, error)
	GetPolicy(ctx context.Context, a resource.AccountID, arn string) (ManagedPolicy, error)
	// CreatePolicyVersion adds the next version, v<n>, and can make it the
	// default. A sixth version is ResourceExhausted.
	CreatePolicyVersion(
		ctx context.Context, a resource.AccountID, arn, document string, setAsDefault bool,
	) (PolicyVersion, error)
	// GetPolicyVersion returns one stored version, including its document.
	GetPolicyVersion(ctx context.Context, a resource.AccountID, arn, versionID string) (PolicyVersion, error)
	ListPolicyVersions(
		ctx context.Context, a resource.AccountID, arn, marker string, maxItems int,
	) (PolicyVersionPage, error)
	ListPolicies(ctx context.Context, a resource.AccountID, pathPrefix string) ([]ManagedPolicy, error)
	DeletePolicy(ctx context.Context, a resource.AccountID, arn string) error
	// SetDefaultPolicyVersion makes version the policy's operative version.
	SetDefaultPolicyVersion(ctx context.Context, a resource.AccountID, arn, version string) error
	// DeletePolicyVersion removes a non-default version. The default version
	// is Conflict.
	DeletePolicyVersion(ctx context.Context, a resource.AccountID, arn, versionID string) error
	// The managed and inline policy calls of a user, group or role take the
	// AuthorizedARN the caller was authorized on. It must match the entity's
	// current ARN on every read, or the call is a ConcurrentModification
	// (Changed) and nothing is written.
	AttachPolicy(ctx context.Context, a resource.AccountID, kind Entity, name, arn string, want AuthorizedARN) error
	DetachPolicy(ctx context.Context, a resource.AccountID, kind Entity, name, arn string, want AuthorizedARN) error
	ListAttachedPolicies(
		ctx context.Context, a resource.AccountID, kind Entity, name string, want AuthorizedARN,
	) ([]ManagedPolicy, error)

	PutInlinePolicy(
		ctx context.Context, a resource.AccountID, kind Entity, name, policy, document string, want AuthorizedARN,
	) error
	GetInlinePolicy(
		ctx context.Context, a resource.AccountID, kind Entity, name, policy string, want AuthorizedARN,
	) (string, error)
	DeleteInlinePolicy(
		ctx context.Context, a resource.AccountID, kind Entity, name, policy string, want AuthorizedARN,
	) error
	ListInlinePolicies(
		ctx context.Context, a resource.AccountID, kind Entity, name string, want AuthorizedARN,
	) ([]string, error)

	TagPolicy(ctx context.Context, a resource.AccountID, arn string, tags []Tag) error
	UntagPolicy(ctx context.Context, a resource.AccountID, arn string, keys []string) error
	ListPolicyTags(ctx context.Context, a resource.AccountID, arn, marker string, maxItems int) (TagPage, error)

	// ListVirtualMFADevices lists every device of the account, filtered by
	// assignment status. Marker is the last serial number of the previous page.
	ListVirtualMFADevices(
		ctx context.Context, a resource.AccountID, assignment MFADeviceAssignment, marker string, maxItems int,
	) (VirtualMFADevicePage, error)

	// ListMFADevices lists the devices enabled for one user. The user
	// argument is the AWS UserName, not an ARN. want must be the user's ARN
	// for the whole read.
	ListMFADevices(
		ctx context.Context, a resource.AccountID, user, marker string, maxItems int, want AuthorizedARN,
	) (MFADevicePage, error)

	// The MFA device argument is the device serial number, the ARN the AWS
	// Query API calls SerialNumber.
	GetMFADevice(ctx context.Context, a resource.AccountID, serial string) (MFADevice, error)
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
