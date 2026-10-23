package iam

import (
	"context"
	"errors"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// AuthorizedARN is the resource ARN of one allowed authorization decision.
// Only Authorize builds a non-zero one: its field is unexported, and internal/hygiene
// fails the build for any other literal of it (#342). Every Admin method that
// acts on a named user, group or role after authorization takes one, compares
// it with the ARN it reads, and answers a mismatch as ConcurrentModification
// (Changed) with no data and no write. The zero value authorizes nothing, and
// every such method refuses it before it reads anything.
type AuthorizedARN struct{ arn string }

// String is the authorized ARN; the zero value is empty.
func (a AuthorizedARN) String() string { return a.arn }

// IsZero reports the zero value, which authorizes nothing.
func (a AuthorizedARN) IsZero() bool { return a.arn == "" }

// Require refuses the zero value: a call that reaches a backend without an
// authorization is an internal error, never an unchecked write.
func (a AuthorizedARN) Require() error {
	if a.arn == "" {
		return Unbound()
	}
	return nil
}

// Bind checks current, the ARN a backend has just read, against the
// authorized one: the zero value is Unbound, another ARN is Changed(msg)
// (UserChanged, GroupChanged, RoleChanged).
func (a AuthorizedARN) Bind(current, msg string) error {
	if err := a.Require(); err != nil {
		return err
	}
	if current != a.arn {
		return changed(msg)
	}
	return nil
}

// Unbound is the internal error of an Admin call made with the zero
// AuthorizedARN. The message stays in the log, never on the wire.
func Unbound() error {
	return resource.Internal(errors.New("iam: admin call without an authorized ARN"))
}

// Authorize authorizes c for action on arn, as Check does, and returns the
// binding the Admin methods take. It is the only constructor of
// AuthorizedARN. An empty arn (an action whose required ARN member is
// missing) is checked as before and returns the zero value, which every
// bound Admin method refuses.
func Authorize(
	ctx context.Context, a Authorizer, c resource.Caller, action, arn string,
) (AuthorizedARN, error) {
	if err := Check(ctx, a, c, action, arn); err != nil {
		return AuthorizedARN{}, err
	}
	return AuthorizedARN{arn: arn}, nil
}
