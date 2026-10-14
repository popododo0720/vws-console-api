package iam

import (
	"context"
	"strings"
	"sync"
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

// Fake is an in-memory IAM: keys plus identity statements per principal ARN,
// evaluated as explicit deny, then allow, then implicit deny. It stands in for
// the vws-iam gRPC client in tests and the fake backend.
type Fake struct {
	mu    sync.RWMutex
	keys  map[string]SigningCredential
	stmts map[string][]Statement
}

// NewFake returns an empty fake.
func NewFake() *Fake {
	return &Fake{keys: map[string]SigningCredential{}, stmts: map[string][]Statement{}}
}

// AddKey stores a credential.
func (f *Fake) AddKey(c SigningCredential) {
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

// GetSigningCredential returns a stored credential.
func (f *Fake) GetSigningCredential(_ context.Context, accessKey string) (SigningCredential, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	c, ok := f.keys[accessKey]
	if !ok {
		return SigningCredential{}, ErrUnknownKey
	}
	return c, nil
}

// Authorize evaluates the principal's statements.
func (f *Fake) Authorize(_ context.Context, req Request) (Decision, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	allowed := false
	for _, s := range f.stmts[req.Principal.ARN] {
		if !matchAny(s.Actions, req.Action, true) || !matchAny(s.Resources, req.Resource, false) {
			continue
		}
		if s.Effect == Deny {
			return Decision{Reason: "explicit deny"}, nil
		}
		if s.Effect == Allow {
			allowed = true
		}
	}
	if allowed {
		return Decision{Allowed: true, Reason: "allowed by identity policy"}, nil
	}
	return Decision{Reason: "implicit deny"}, nil
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
