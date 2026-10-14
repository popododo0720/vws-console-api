// Package iam is console-api's view of vws-iam: resolving an access key to its
// signing credential, and authorizing one action on one resource. Static
// serves the bootstrap root key, Fake is an in-memory stand-in until the
// vws/iam/v1 gRPC client lands (vws-proto#24), and Cache and WithRoot compose
// them.
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

// SigningCredential is what SigV4 needs to check a signature, and who signed.
type SigningCredential struct {
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

// Client is the part of vws-iam console-api calls on every request.
type Client interface {
	GetSigningCredential(ctx context.Context, accessKey string) (SigningCredential, error)
	Authorize(ctx context.Context, req Request) (Decision, error)
}

// Authorizer is the per-request half of Client.
type Authorizer interface {
	Authorize(ctx context.Context, req Request) (Decision, error)
}

// RootARN is the ARN of an account's root user.
func RootARN(account resource.AccountID) string {
	return "arn:vws:iam::" + account.String() + ":root"
}

// KeyStore adapts a Client to the sigv4 key hook.
func KeyStore(c Client) sigv4.KeyStore { return keyStore{c} }

type keyStore struct{ c Client }

func (k keyStore) SigningCredential(ctx context.Context, accessKey string) (sigv4.Credential, error) {
	cred, err := k.c.GetSigningCredential(ctx, accessKey)
	if err != nil {
		return sigv4.Credential{}, err
	}
	return sigv4.Credential{
		AccessKey: cred.AccessKey, Secret: cred.Secret, Account: cred.Principal.Account,
		Principal: cred.Principal.ARN, Root: cred.Principal.Root,
		SessionToken: cred.SessionToken, Expires: cred.Expires,
	}, nil
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
