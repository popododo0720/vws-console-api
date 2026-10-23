package iam

import (
	"errors"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Shared AWS rules and messages for users and groups, so every Admin backend
// validates and answers the same way.

// MaxGroupsPerUser is the AWS GroupsPerUser quota.
const MaxGroupsPerUser = maxGroupsPerUser

// Delete conflict messages, as AWS words them.
const (
	UserDeleteConflict = "Cannot delete entity, must delete login profile, access keys, policies and " +
		"group memberships first."
	GroupDeleteConflict = "Cannot delete entity, must remove users and policies from group first."
	// UserChanged and GroupChanged are the ConcurrentModification when the
	// entity's ARN moved between the caller's authorization and the change.
	UserChanged  = "The user changed while the request was in flight."
	GroupChanged = "The group changed while the request was in flight."
)

// ConcurrentModification is the Field that marks a Conflict as the AWS
// ConcurrentModification rather than a DeleteConflict.
const ConcurrentModification = "ConcurrentModification"

// CheckUserName validates a new user name for field (userName or
// newUserName): the AWS pattern, 1 to 64 characters, and not the reserved
// account root name.
func CheckUserName(field, name string) error {
	if err := checkName(entityName, field, name); err != nil {
		return err
	}
	if strings.EqualFold(name, RootUserName) {
		return reservedRoot(field)
	}
	return nil
}

func reservedRoot(field string) error {
	return resource.Invalid(field, "the user name "+RootUserName+" is reserved for the account root")
}

// CheckGroupName validates a group name for field: the AWS pattern, 1 to 128
// characters.
func CheckGroupName(field, name string) error { return checkName(groupName, field, name) }

// NormalizePath validates an IAM path for field and returns "/" for an empty
// one.
func NormalizePath(field, path string) (string, error) { return normPathAs(path, field) }

// EntityNotFound is the NoSuchEntity error for a user or group ("user",
// "group").
func EntityNotFound(what, name string) error { return notFound(what, name) }

// EntityExists is the EntityAlreadyExists error for a user or group ("User",
// "Group").
func EntityExists(what, name string) error { return exists(what, name) }

// Conflict is a DeleteConflict.
func Conflict(msg string) error { return conflict(msg) }

// Changed is the ConcurrentModification of a change whose entity no longer
// has the ARN the caller was authorized on (UserChanged, GroupChanged).
func Changed(msg string) error { return changed(msg) }

// IsChanged reports whether err is a Changed error.
func IsChanged(err error) bool {
	var e *resource.Error
	return errors.As(err, &e) && e.Code == resource.CodeConflict && e.Field == ConcurrentModification
}

// GroupsPerUserExceeded is the LimitExceeded error of AddUserToGroup.
func GroupsPerUserExceeded() error { return quota(groupsPerUserMsg) }

const groupsPerUserMsg = "Cannot exceed quota for GroupsPerUser: 10"
