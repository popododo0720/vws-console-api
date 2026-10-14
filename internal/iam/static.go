package iam

import (
	"context"
	"crypto/subtle"
	"sync"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// Static serves one long-term key as the account root user. It is the
// -access-key/-secret pair from vws-console-api-credentials, kept so existing
// clients keep working while vws-iam takes over every other key.
type Static struct {
	key      Key
	mu       sync.Mutex
	password string // argon2id hash; empty disables root sign-in
	guard    *guard
	sessions *sessionTable
	dummy    func() string
}

// NewStatic returns the root credential for accessKey.
func NewStatic(accessKey, secret string, account resource.AccountID) *Static {
	return &Static{key: Key{
		AccessKey: accessKey, Secret: secret,
		Principal: Principal{Account: account, ARN: RootARN(account), Root: true},
	}, sessions: newSessionTable(), guard: newGuard(), dummy: sync.OnceValue(newDummyHash)}
}

// Authenticate verifies a signature made with its own key, locally, with the
// static secret. Any other key is ErrUnknownKey. A session token is refused.
func (s *Static) Authenticate(_ context.Context, req sigv4.AuthRequest) (Principal, error) {
	if subtle.ConstantTimeCompare([]byte(req.AccessKeyID), []byte(s.key.AccessKey)) != 1 {
		return Principal{}, ErrUnknownKey
	}
	return verifyKey(s.key, req, time.Now())
}

// Authorize allows the root user of its own account and nobody else.
func (s *Static) Authorize(_ context.Context, req Request) (Decision, error) {
	if req.Principal.Root && req.Principal.Account == s.key.Principal.Account && req.Principal.ARN == s.key.Principal.ARN {
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

func (w withRoot) Authenticate(ctx context.Context, req sigv4.AuthRequest) (Principal, error) {
	if subtle.ConstantTimeCompare([]byte(req.AccessKeyID), []byte(w.root.key.AccessKey)) == 1 {
		return w.root.Authenticate(ctx, req)
	}
	return w.next.Authenticate(ctx, req)
}

func (w withRoot) Authorize(ctx context.Context, req Request) (Decision, error) {
	// Static.Authorize never fails; a non-root principal falls through.
	if d, err := w.root.Authorize(ctx, req); err == nil && d.Allowed {
		return d, nil
	}
	return w.next.Authorize(ctx, req)
}
