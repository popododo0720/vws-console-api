package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Console sign-in limits.
const (
	// SessionTTL is how long a console session lasts, like the AWS console.
	SessionTTL = 12 * time.Hour
	// MaxLoginFailures failed sign-ins in a row lock a user out for LockoutPeriod.
	MaxLoginFailures = 5
	// LockoutPeriod is how long a lockout lasts.
	LockoutPeriod = 15 * time.Minute
	// RootUserName signs in as the account root. No IAM user may take it.
	RootUserName = "root"
)

// LoginRequest maps to vws-iam AuthService.Login. SourceIP is the client
// address the surface saw (Authenticate's source_ip, field 9).
type LoginRequest struct {
	Account  resource.AccountID
	UserName string
	Password string
	MFACode  string
	SourceIP string
}

// Session is a console session. Token is set only by Login: it is the bearer
// secret the surface puts in an HttpOnly cookie, and only its hash is kept.
type Session struct {
	Token     string
	Principal Principal
	Expires   time.Time
}

// Sessions is the console sign-in half of vws-iam AuthService.
type Sessions interface {
	Login(ctx context.Context, req LoginRequest) (Session, error)
	// ValidateSession returns the session for token, without the token.
	ValidateSession(ctx context.Context, token string) (Session, error)
	// Logout revokes token. An unknown token is not an error.
	Logout(ctx context.Context, token string) error
}

// errLogin is the one sign-in failure: it never says which part was wrong
// or whether the user exists.
func errLogin() error {
	return resource.Unauthenticated("The username or password you entered is incorrect.")
}

func errSession() error { return resource.Unauthenticated("session expired or signed out") }

// sessionTable holds sessions by token hash.
type sessionTable struct {
	mu   sync.Mutex
	byID map[[32]byte]Session
}

func newSessionTable() *sessionTable { return &sessionTable{byID: map[[32]byte]Session{}} }

func tokenID(token string) [32]byte { return sha256.Sum256([]byte(token)) }

func (t *sessionTable) open(p Principal, now time.Time) (Session, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return Session{}, fmt.Errorf("session token: %w", err)
	}
	s := Session{Token: base64.RawURLEncoding.EncodeToString(b), Principal: p, Expires: now.Add(SessionTTL)}
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, old := range t.byID { // drop expired sessions as new ones open
		if !now.Before(old.Expires) {
			delete(t.byID, id)
		}
	}
	t.byID[tokenID(s.Token)] = Session{Principal: p, Expires: s.Expires}
	return s, nil
}

func (t *sessionTable) get(token string, now time.Time) (Session, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.byID[tokenID(token)]
	if !ok {
		return Session{}, false
	}
	if !now.Before(s.Expires) {
		delete(t.byID, tokenID(token))
		return Session{}, false
	}
	return s, true
}

func (t *sessionTable) close(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.byID, tokenID(token))
}

// lockout counts consecutive failures per key.
type lockout struct {
	failures int
	until    time.Time
}
