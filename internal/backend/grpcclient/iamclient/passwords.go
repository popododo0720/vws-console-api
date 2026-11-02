package iamclient

import (
	"context"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// ChangePassword implements iam.Admin over UserService.ChangePassword. The
// user is read first so the change is bound to the ARN the caller was
// authorized on. The change runs once, never retried: a repeat after a write
// that landed would verify the old password against the new hash and answer
// AccessDenied for a change that succeeded. Neither password reaches the span,
// the log or an error.
func (a STSAdmin) ChangePassword(
	ctx context.Context, account resource.AccountID, name, oldPassword, newPassword string, want iam.AuthorizedPrincipal,
) (err error) {
	ctx, end := a.observe(ctx, "ChangePassword", true, account, name, "")
	defer func() { end(err) }()
	if err := want.Require(); err != nil {
		return err
	}
	if !entityName(name) {
		return entityNotFound("user", name)
	}
	raw, u, err := a.rawUser(ctx, account, name)
	if err != nil {
		return err
	}
	if err := want.Bind(u.ARN, iam.UserChanged); err != nil {
		return err
	}
	_, err = call(ctx, a.users.ChangePassword, &iamv1.ChangePasswordRequest{
		Name: raw.GetName(), OldPassword: oldPassword, NewPassword: newPassword,
	})
	return changePasswordError(err, name)
}

// changePasswordError maps a vws-iam ChangePassword failure to its AWS
// error. vws-iam answers a wrong old password, and a user with no password,
// as UNAUTHENTICATED; that is AccessDenied here, never a signature failure,
// because the request signature was already verified. A password the policy
// refuses is PasswordPolicyViolation, and a lost write race is
// EntityTemporarilyUnmodifiable.
func changePasswordError(err error, name string) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() { //nolint:exhaustive // the rest is entityError's.
	case codes.Unauthenticated:
		return iam.OldPasswordRejected()
	case codes.InvalidArgument:
		return resource.Invalid("Password", st.Message())
	case codes.Aborted:
		return iam.EntityTemporarilyUnmodifiable(name)
	}
	return entityError(err, "user", name)
}
