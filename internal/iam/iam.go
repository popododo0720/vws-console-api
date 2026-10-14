// Package iam is console-api's view of vws-iam AuthService: Authenticate
// checks a SigV4 signature and names the principal, and Authorize decides one
// action on one resource. Access-key secrets stay inside the authenticator;
// console-api never fetches them. Static serves the bootstrap root key, Fake
// is an in-memory stand-in until the vws/iam/v1 gRPC client lands
// (vws-proto#24), and WithRoot composes them.
package iam

import (
	"context"
	"errors"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// ErrUnknownKey is returned for an access key IAM does not hold.
var ErrUnknownKey = sigv4.ErrUnknownKey

// Principal is who a credential acts as.
type Principal struct {
	Account resource.AccountID
	ARN     string
	Root    bool
}

// Key is an access key as an authenticator holds it. SessionToken and
// Expires are set for temporary (STS) keys.
type Key struct {
	AccessKey    string
	Secret       string
	SessionToken string
	Expires      time.Time
	Principal    Principal
}

// Request asks whether Principal may perform Action on Resource.
type Request struct {
	Principal Principal
	Action    string
	Resource  string
	Context   map[string]string
}

// Decision is the answer. Reason is for logs, not for the wire.
type Decision struct {
	Allowed bool
	Reason  string
}

// Client is the part of vws-iam AuthService console-api calls on every
// request. Authenticate returns ErrUnknownKey for a key it does not hold and
// an Unauthenticated *resource.Error for a bad signature or session token.
//
// The Sessions half serves console sign-in (vws-iam AuthService.Login).
type Client interface {
	Authenticate(ctx context.Context, req sigv4.AuthRequest) (Principal, error)
	Authorize(ctx context.Context, req Request) (Decision, error)
	Sessions
}

// Authorizer is the per-request half of Client.
type Authorizer interface {
	Authorize(ctx context.Context, req Request) (Decision, error)
}

// RootARN is the ARN of an account's root user.
func RootARN(account resource.AccountID) string {
	return "arn:vws:iam::" + account.String() + ":root"
}

// Authenticator adapts a Client to the sigv4 verifier.
func Authenticator(c Client) sigv4.Authenticator { return authenticator{c} }

type authenticator struct{ c Client }

func (a authenticator) Authenticate(ctx context.Context, req sigv4.AuthRequest) (sigv4.Identity, error) {
	p, err := a.c.Authenticate(ctx, req)
	if err != nil {
		return sigv4.Identity{}, err
	}
	return sigv4.Identity{Account: p.Account, Principal: p.ARN, Root: p.Root}, nil
}

// verifyKey is the local check Static and Fake share: session token and
// expiry first, then the signature with the key's own secret.
func verifyKey(k Key, req sigv4.AuthRequest, now time.Time) (Principal, error) {
	if err := sigv4.CheckSession(k.SessionToken, req.SessionToken, k.Expires, now); err != nil {
		return Principal{}, err
	}
	if !req.VerifiedBy(k.Secret) {
		return Principal{}, resource.Unauthenticated("signature mismatch")
	}
	return k.Principal, nil
}

// Check authorizes c for action on arn. A nil authorizer, an error, or a deny
// all return PermissionDenied: authorization fails closed.
func Check(ctx context.Context, a Authorizer, c resource.Caller, action, arn string) error {
	if a == nil {
		return resource.Denied("no authorizer configured")
	}
	d, err := a.Authorize(ctx, Request{
		Principal: Principal{Account: c.Account, ARN: c.Principal, Root: c.Root},
		Action:    action, Resource: arn,
	})
	if err != nil {
		var re *resource.Error
		if errors.As(err, &re) {
			return re
		}
		return &resource.Error{Code: resource.CodeUnavailable, Message: "authorization unavailable"}
	}
	if !d.Allowed {
		return resource.Denied("You are not authorized to perform this operation.")
	}
	return nil
}
