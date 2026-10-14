package iam

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// Effect is Allow or Deny.
type Effect string

// The two statement effects.
const (
	Allow Effect = "Allow"
	Deny  Effect = "Deny"
)

// Statement is one identity-policy statement. Actions and Resources take *
// and ? wildcards; actions match without regard to case, as in AWS.
type Statement struct {
	Effect    Effect
	Actions   []string
	Resources []string
}

// Fake is an in-memory IAM: users, groups, roles, policies, access keys and
// STS sessions per account (store.go), plus raw statements per principal ARN
// for tests. Policies evaluate as explicit deny, then allow, then implicit
// deny. It stands in for the vws-iam gRPC client until vws-proto#24, and
// nothing in it survives a restart.
type Fake struct {
	// Now is the clock for creation times and session expiry. Nil uses time.Now.
	Now      func() time.Time
	mu       sync.RWMutex
	keys     map[string]Key
	stmts    map[string][]Statement
	accounts map[resource.AccountID]*store
	sessions *sessionTable
	guard    *guard
	dummy    func() string
}

// NewFake returns an empty fake.
func NewFake() *Fake {
	return &Fake{keys: map[string]Key{}, stmts: map[string][]Statement{}, accounts: map[resource.AccountID]*store{},
		sessions: newSessionTable(), guard: newGuard(), dummy: sync.OnceValue(newDummyHash)}
}

func (f *Fake) now() time.Time {
	if f.Now != nil {
		return f.Now().UTC()
	}
	return time.Now().UTC()
}

// AddKey stores a key with its secret.
func (f *Fake) AddKey(c Key) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[c.AccessKey] = c
}

// AddStatement attaches a statement to a principal.
func (f *Fake) AddStatement(principalARN string, s Statement) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stmts[principalARN] = append(f.stmts[principalARN], s)
}

// Authenticate verifies with the stored secret, inside the fake.
func (f *Fake) Authenticate(_ context.Context, req sigv4.AuthRequest) (Principal, error) {
	f.mu.RLock()
	k, ok := f.keys[req.AccessKeyID]
	f.mu.RUnlock()
	if !ok {
		return Principal{}, ErrUnknownKey
	}
	return verifyKey(k, req, f.now())
}

// Authorize evaluates the principal's raw statements and, for an IAM user
// or an assumed role, its identity policies: inline and attached, and for a
// user those of its groups too.
func (f *Fake) Authorize(_ context.Context, req Request) (Decision, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var stmts []policyStatement
	for _, s := range f.stmts[req.Principal.ARN] {
		stmts = append(stmts, policyStatement{effect: s.Effect, action: s.Actions, resource: s.Resources})
	}
	if st := f.accounts[req.Principal.Account]; st != nil {
		stmts = append(stmts, st.statementsFor(req.Principal.ARN)...)
	}
	return evaluate(stmts, req.Action, req.Resource), nil
}

func matchAny(patterns []string, s string, fold bool) bool {
	if fold {
		s = strings.ToLower(s)
	}
	for _, p := range patterns {
		if fold {
			p = strings.ToLower(p)
		}
		if wildcard(p, s) {
			return true
		}
	}
	return false
}

// wildcard matches * (any run, including /) and ? (one byte).
func wildcard(p, s string) bool {
	pi, si, star, mark := 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == s[si]):
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
