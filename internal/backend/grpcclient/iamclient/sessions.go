package iamclient

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

var _ iam.Client = (*Client)(nil)

// unavailable is the fail-closed answer for a transport error or anything
// vws-iam did not mean as a verdict. vws-iam's own message is not echoed.
func unavailable(what string) error {
	return &resource.Error{Code: resource.CodeUnavailable, Message: what + " unavailable"}
}

// principalOf maps a vws-iam Principal to the console's, keeping the parts
// vws-iam rechecks on Authorize.
func principalOf(pr *iamv1.Principal) (iam.Principal, error) {
	account, err := resource.Parse[resource.AccountID](pr.GetProject())
	if err != nil {
		return iam.Principal{}, fmt.Errorf("vws-iam returned project %q: %w", pr.GetProject(), err)
	}
	if pr.GetArn() == "" {
		return iam.Principal{}, fmt.Errorf("vws-iam returned a principal without an ARN")
	}
	return iam.Principal{Account: account, ARN: pr.GetArn(), Root: pr.GetType() == iamv1.PrincipalType_PRINCIPAL_TYPE_ROOT, Ref: refOf(pr)}, nil
}

// Login implements iam.Sessions over vws-iam AuthService.Login. It is not
// retried: a sign-in opens a session and moves lockout counters. Every
// verdict against the credentials is the same uniform 401 the in-memory IAM
// answers; RESOURCE_EXHAUSTED is 429 and UNAVAILABLE is busy (503 with
// Retry-After); anything else fails closed as unavailable.
func (c *Client) Login(ctx context.Context, r iam.LoginRequest) (iam.Session, error) {
	resp, err := call(ctx, c.auth.Login, &iamv1.LoginRequest{
		Project: r.Account.String(), UserName: r.UserName, Password: r.Password, TotpCode: r.MFACode, SourceIp: r.SourceIP,
	})
	if err != nil {
		return iam.Session{}, loginError(err)
	}
	p, err := principalOf(resp.GetPrincipal())
	if err != nil || resp.GetSessionToken() == "" {
		c.revoke(ctx, resp.GetSessionToken())
		return iam.Session{}, unavailable("sign-in")
	}
	if resp.GetPasswordResetRequired() {
		// The console has no password-change flow yet, so a session that
		// must change its password first is not handed out.
		c.revoke(ctx, resp.GetSessionToken())
		return iam.Session{}, resource.Denied("Your password must be reset before you can sign in to the console.")
	}
	return iam.Session{Token: resp.GetSessionToken(), Principal: p, Expires: resp.GetExpireTime().AsTime()}, nil
}

// revoke is a best-effort Logout of a session Login will not hand out.
func (c *Client) revoke(ctx context.Context, token string) {
	if token != "" {
		_ = c.Logout(ctx, token) //nolint:errcheck // best effort: an unrevoked session still expires on its own.
	}
}

func loginError(err error) error {
	switch status.Code(err) { //nolint:exhaustive // every other code fails closed below.
	case codes.Unauthenticated, codes.PermissionDenied, codes.NotFound, codes.InvalidArgument:
		return iam.LoginFailed()
	case codes.ResourceExhausted:
		return &resource.Error{Code: resource.CodeResourceExhausted, Message: "too many sign-in attempts; retry later"}
	case codes.Unavailable:
		return iam.Busy()
	default:
		return unavailable("sign-in")
	}
}

// ValidateSession implements iam.Sessions over AuthService.ValidateSession
// (read-only, so UNAVAILABLE is retried). The session has no Token; the
// principal's Ref carries it as a ProofSession so STS calls can name the
// caller to vws-iam. Ref.Proof is a credential and is never logged.
func (c *Client) ValidateSession(ctx context.Context, token string) (iam.Session, error) {
	resp, err := retry(ctx, c.backoff, c.auth.ValidateSession, &iamv1.ValidateSessionRequest{SessionToken: token})
	if err != nil {
		if status.Code(err) == codes.Unauthenticated {
			return iam.Session{}, iam.SessionInvalid()
		}
		return iam.Session{}, unavailable("session check")
	}
	p, err := principalOf(resp.GetPrincipal())
	if err != nil {
		return iam.Session{}, unavailable("session check")
	}
	p.Ref.ProofKind, p.Ref.Proof = resource.ProofSession, token
	return iam.Session{Principal: p, Expires: resp.GetExpireTime().AsTime()}, nil
}

// Logout implements iam.Sessions over AuthService.Logout. Revoking is
// idempotent, so it is retried, and an unknown token is not an error.
func (c *Client) Logout(ctx context.Context, token string) error {
	_, err := retry(ctx, c.backoff, c.auth.Logout, &iamv1.LogoutRequest{SessionToken: token})
	if err != nil && status.Code(err) != codes.Unauthenticated {
		return unavailable("sign-out")
	}
	return nil
}
