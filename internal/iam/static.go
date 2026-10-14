package iam

import (
	"context"
	"crypto/subtle"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Static serves one long-term key as the account root user. It is the
// -access-key/-secret pair from vws-console-api-credentials, kept so existing
// clients keep working while vws-iam takes over every other key.
type Static struct {
	cred SigningCredential
}

// NewStatic returns the root credential for accessKey.
func NewStatic(accessKey, secret string, account resource.AccountID) *Static {
	return &Static{cred: SigningCredential{
		AccessKey: accessKey, Secret: secret,
		Principal: Principal{Account: account, ARN: RootARN(account), Root: true},
	}}
}

// GetSigningCredential returns the root credential for its own key only.
func (s *Static) GetSigningCredential(_ context.Context, accessKey string) (SigningCredential, error) {
	if subtle.ConstantTimeCompare([]byte(accessKey), []byte(s.cred.AccessKey)) != 1 {
		return SigningCredential{}, ErrUnknownKey
	}
	return s.cred, nil
}

// Authorize allows the root user of its own account and nobody else.
func (s *Static) Authorize(_ context.Context, req Request) (Decision, error) {
	if req.Principal.Root && req.Principal.Account == s.cred.Principal.Account && req.Principal.ARN == s.cred.Principal.ARN {
		return Decision{Allowed: true, Reason: "account root"}, nil
	}
	return Decision{Reason: "implicit deny"}, nil
}

// WithRoot answers for the root key with root and sends every other key and
// principal to next.
func WithRoot(root *Static, next Client) Client { return withRoot{root: root, next: next} }

type withRoot struct {
	root *Static
	next Client
}

func (w withRoot) GetSigningCredential(ctx context.Context, accessKey string) (SigningCredential, error) {
	if cred, err := w.root.GetSigningCredential(ctx, accessKey); err == nil {
		return cred, nil
	}
	return w.next.GetSigningCredential(ctx, accessKey)
}

func (w withRoot) Authorize(ctx context.Context, req Request) (Decision, error) {
	// Static.Authorize never fails; a non-root principal falls through.
	if d, err := w.root.Authorize(ctx, req); err == nil && d.Allowed {
		return d, nil
	}
	return w.next.Authorize(ctx, req)
}
