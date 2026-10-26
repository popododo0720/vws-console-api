package iam

import (
	"context"
	"errors"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// AuthorizedPrincipal is the principal of one allowed authorization decision,
// bound by its resource ARN (#517 class 5). Only Authorize builds a non-zero
// one: its field is unexported, and internal/hygiene type-checks package iam
// and fails the build for any other literal, conversion or field use of it,
// however the type is spelled (#342, #355). Every Admin method that acts on a
// named user, group or role after authorization takes one, compares it with
// the ARN it reads, and answers a mismatch as ConcurrentModification (Changed)
// with no data and no write. The zero value authorizes nothing, and every such
// method refuses it before it reads anything.
type AuthorizedPrincipal struct{ arn string }

// String is the authorized ARN; the zero value is empty.
func (a AuthorizedPrincipal) String() string { return a.arn }

// IsZero reports the zero value, which authorizes nothing.
func (a AuthorizedPrincipal) IsZero() bool { return a.arn == "" }

// Require refuses the zero value: a call that reaches a backend without an
// authorization is an internal error, never an unchecked write.
func (a AuthorizedPrincipal) Require() error {
	if a.arn == "" {
		return Unbound()
	}
	return nil
}

// Bind checks current, the ARN a backend has just read, against the
// authorized one: the zero value is Unbound, another ARN is Changed(msg)
// (UserChanged, GroupChanged, RoleChanged).
func (a AuthorizedPrincipal) Bind(current, msg string) error {
	if err := a.Require(); err != nil {
		return err
	}
	if current != a.arn {
		return changed(msg)
	}
	return nil
}

// Unbound is the internal error of an Admin call made with the zero
// AuthorizedPrincipal. The message stays in the log, never on the wire.
func Unbound() error {
	return resource.Internal(errors.New("iam: admin call without an authorized ARN"))
}

// Authorize authorizes c for action on arn, as Check does, and returns the
// binding the Admin methods take. It is the only constructor of
// AuthorizedPrincipal. An empty arn (an action whose required ARN member is
// missing) is checked as before and returns the zero value, which every
// bound Admin method refuses.
func Authorize(
	ctx context.Context, a Authorizer, c resource.Caller, action, arn string,
) (AuthorizedPrincipal, error) {
	if err := Check(ctx, a, c, action, arn); err != nil {
		return AuthorizedPrincipal{}, err
	}
	return AuthorizedPrincipal{arn: arn}, nil
}
