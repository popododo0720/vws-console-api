package iam

import (
	"strconv"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Shared AWS rules and messages for the managed and inline policies of a
// user, group or role, so every Admin backend validates and answers the same
// way.

// RoleChanged is the ConcurrentModification when a role's ARN moved between
// the caller's authorization and the change.
const RoleChanged = "The role changed while the request was in flight."

// MaxAttachedPolicies is the AWS PoliciesPerUser, PoliciesPerGroup and
// default PoliciesPerRole quota of attached managed policies.
const MaxAttachedPolicies = maxAttachedPerEntity

// ChangedFor is the ConcurrentModification of a policy call on kind.
func ChangedFor(kind Entity) error {
	switch kind {
	case EntityGroup:
		return changed(GroupChanged)
	case EntityRole:
		return changed(RoleChanged)
	case EntityUser:
	}
	return changed(UserChanged)
}

func entityWord(kind Entity) string {
	switch kind {
	case EntityGroup:
		return "Group"
	case EntityRole:
		return "Role"
	case EntityUser:
	}
	return "User"
}

// AttachedQuotaExceeded is the LimitExceeded error of attaching one managed
// policy more than MaxAttachedPolicies to kind.
func AttachedQuotaExceeded(kind Entity) error {
	return quota("Cannot exceed quota for PoliciesPer" + entityWord(kind) + ": " + strconv.Itoa(maxAttachedPerEntity))
}

// PolicyNotAttached is the NoSuchEntity error of detaching a managed policy
// the entity does not have.
func PolicyNotAttached(arn string) error {
	return &resource.Error{Code: resource.CodeNotFound, Message: "Policy " + arn + " was not found."}
}

// PolicyNotAttachable is the NoSuchEntity error of a managed policy ARN that
// does not name a policy of the account.
func PolicyNotAttachable(arn string) error {
	return &resource.Error{Code: resource.CodeNotFound, Message: "Policy " + arn + " does not exist or is not attachable."}
}

// InlinePolicyNotFound is the NoSuchEntity error of an inline policy name
// the entity does not have.
func InlinePolicyNotFound(kind Entity, policy string) error {
	return notFound(kind.String()+" policy", policy)
}

// CheckInlinePolicyName validates an inline policy name: the AWS pattern,
// 1 to 128 characters.
func CheckInlinePolicyName(name string) error { return checkName(policyName, "policyName", name) }

// ValidateIdentityPolicy checks an inline identity policy document against
// the policy grammar. Its size is checked per entity by
// CheckInlinePolicySize.
func ValidateIdentityPolicy(doc string) error {
	_, err := parseDoc(doc, false)
	return err
}

// InlinePolicySizeLimit is the AWS aggregate size, in characters without
// white space, of the inline policies of kind: 2,048 for a user, 5,120 for
// a group and 10,240 for a role.
func InlinePolicySizeLimit(kind Entity) int {
	switch kind {
	case EntityGroup:
		return 5120
	case EntityRole:
		return 10240
	case EntityUser:
	}
	return 2048
}

// InlinePolicySize is the size AWS counts for an inline policy document:
// its characters other than white space.
func InlinePolicySize(doc string) int {
	n := 0
	for _, r := range doc {
		switch r {
		case ' ', '\t', '\n', '\r':
		default:
			n++
		}
	}
	return n
}

// CheckInlinePolicySize is the LimitExceeded error when the inline policy
// documents of the entity name of kind exceed InlinePolicySizeLimit.
func CheckInlinePolicySize(kind Entity, name string, docs map[string]string) error {
	total := 0
	for _, d := range docs {
		total += InlinePolicySize(d)
	}
	if limit := InlinePolicySizeLimit(kind); total > limit {
		return quota("Maximum policy size of " + strconv.Itoa(limit) + " bytes exceeded for " +
			kind.String() + " " + name + ".")
	}
	return nil
}
