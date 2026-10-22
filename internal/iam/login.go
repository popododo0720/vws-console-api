package iam

import (
	"context"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

type loginRec struct {
	hash    string
	created time.Time
}

// --- login profiles (Admin) ---

// guardedHash hashes pw in a hashing slot.
func guardedHash(ctx context.Context, g *guard, pw string) (string, error) {
	var hash string
	var err error
	if busyErr := g.hash(ctx, func() { hash, err = hashPassword(pw) }); busyErr != nil {
		return "", busyErr
	}
	return hash, err
}

// guardedVerify checks pw against hash in a hashing slot.
func guardedVerify(ctx context.Context, g *guard, hash, pw string) (bool, error) {
	var ok bool
	err := g.hash(ctx, func() { ok = verifyPassword(hash, pw) })
	return ok, err
}

// CreateLoginProfile implements Admin: it gives user a console password.
func (f *Fake) CreateLoginProfile(ctx context.Context, a resource.AccountID, user, password string) (LoginProfile, error) {
	if err := checkPassword(password); err != nil {
		return LoginProfile{}, err
	}
	hash, err := guardedHash(ctx, f.guard, password)
	if err != nil {
		return LoginProfile{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.account(a).users[user]
	if u == nil {
		return LoginProfile{}, notFound("user", user)
	}
	if u.login != nil {
		return LoginProfile{}, exists("Login Profile for User", user)
	}
	u.login = &loginRec{hash: hash, created: f.now()}
	return LoginProfile{UserName: user, Created: u.login.created}, nil
}

// GetLoginProfile implements Admin.
func (f *Fake) GetLoginProfile(_ context.Context, a resource.AccountID, user string) (LoginProfile, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	u := f.accounts[a].user(user)
	if u == nil || u.login == nil {
		return LoginProfile{}, notFound("Login Profile for User", user)
	}
	return LoginProfile{UserName: user, Created: u.login.created}, nil
}

// UpdateLoginProfile implements Admin: it sets a new password and clears any
// lockout. Existing sessions stay valid until they expire or sign out.
func (f *Fake) UpdateLoginProfile(ctx context.Context, a resource.AccountID, user, password string) error {
	if err := checkPassword(password); err != nil {
		return err
	}
	hash, err := guardedHash(ctx, f.guard, password)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.accounts[a].user(user)
	if u == nil || u.login == nil {
		return notFound("Login Profile for User", user)
	}
	u.login.hash = hash
	f.guard.forget(a, user)
	return nil
}

// DeleteLoginProfile implements Admin.
func (f *Fake) DeleteLoginProfile(_ context.Context, a resource.AccountID, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.accounts[a].user(user)
	if u == nil || u.login == nil {
		return notFound("Login Profile for User", user)
	}
	u.login = nil
	f.guard.forget(a, user)
	return nil
}

func (st *store) user(name string) *userRec {
	if st == nil {
		return nil
	}
	return st.users[name]
}

// --- sign-in (Sessions) ---

// Login implements Sessions. Every failure is the same Unauthenticated error
// and costs one argon2id verification, so it reveals neither whether the user
// exists nor which field was wrong. Hashing runs in a bounded number of
// slots; when they are full the answer is busy (503) before any work.
// MaxLoginFailures in a row from one address lock the user from that
// address only, with exponential backoff. Users have no MFA devices yet
// (vws-iam#6), so any MFA code fails.
func (f *Fake) Login(ctx context.Context, req LoginRequest) (Session, error) {
	now := f.now()
	if f.guard.locked(lockKey(req.Account, req.UserName, req.SourceIP), now) {
		return Session{}, errLogin()
	}
	f.mu.RLock()
	u := f.accounts[req.Account].user(req.UserName)
	hash, p := f.dummy(), Principal{}
	if u != nil && u.login != nil {
		hash, p = u.login.hash, Principal{Account: req.Account, ARN: u.ARN}
	}
	f.mu.RUnlock()
	match, err := guardedVerify(ctx, f.guard, hash, req.Password)
	if err != nil {
		return Session{}, err
	}
	if p.ARN == "" {
		return Session{}, errLogin()
	}
	if !match || req.MFACode != "" {
		f.guard.fail(ctx, req, now)
		return Session{}, errLogin()
	}
	f.guard.succeed(req)
	// Open under the same lock a rename takes. A rename either moves this
	// session, or the user is already moved and the session opens with the
	// new ARN. The hash must still be the one just verified, so a replaced
	// record or a changed password cannot inherit this sign-in.
	f.mu.RLock()
	defer f.mu.RUnlock()
	current := f.accounts[req.Account].user(req.UserName)
	if current == nil || current.login == nil || current.login.hash != hash {
		return Session{}, errLogin()
	}
	return f.sessions.open(Principal{Account: req.Account, ARN: current.ARN}, now)
}

// ValidateSession implements Sessions.
func (f *Fake) ValidateSession(_ context.Context, token string) (Session, error) {
	s, ok := f.sessions.get(token, f.now())
	if !ok {
		return Session{}, errSession()
	}
	return s, nil
}

// Logout implements Sessions.
func (f *Fake) Logout(_ context.Context, token string) error {
	f.sessions.close(token)
	return nil
}

// --- root sign-in ---

// SetPassword enables root console sign-in with password. The process keeps
// only its argon2id hash.
func (s *Static) SetPassword(ctx context.Context, password string) error {
	if err := checkPassword(password); err != nil {
		return err
	}
	hash, err := guardedHash(ctx, s.guard, password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.password = hash
	s.guard.forget(s.key.Principal.Account, RootUserName)
	return nil
}

func (s *Static) isRoot(req LoginRequest) bool {
	return req.UserName == RootUserName && req.Account == s.key.Principal.Account
}

// Login implements Sessions for the account root, with the same bounded
// hashing, per-address lockout and uniform failure as IAM users. Root has no
// MFA device here either.
func (s *Static) Login(ctx context.Context, req LoginRequest) (Session, error) {
	now := time.Now()
	if s.guard.locked(lockKey(req.Account, req.UserName, req.SourceIP), now) {
		return Session{}, errLogin()
	}
	s.mu.Lock()
	hash := s.password
	s.mu.Unlock()
	known := hash != "" && s.isRoot(req)
	if !known {
		hash = s.dummy()
	}
	match, err := guardedVerify(ctx, s.guard, hash, req.Password)
	if err != nil {
		return Session{}, err
	}
	if !known {
		return Session{}, errLogin()
	}
	if !match || req.MFACode != "" {
		s.guard.fail(ctx, req, now)
		return Session{}, errLogin()
	}
	s.guard.succeed(req)
	return s.sessions.open(s.key.Principal, now)
}

// ValidateSession implements Sessions.
func (s *Static) ValidateSession(_ context.Context, token string) (Session, error) {
	sess, ok := s.sessions.get(token, time.Now())
	if !ok {
		return Session{}, errSession()
	}
	return sess, nil
}

// Logout implements Sessions.
func (s *Static) Logout(_ context.Context, token string) error {
	s.sessions.close(token)
	return nil
}

// Login sends the root user name to root and everyone else to next.
func (w withRoot) Login(ctx context.Context, req LoginRequest) (Session, error) {
	if strings.EqualFold(req.UserName, RootUserName) {
		return w.root.Login(ctx, req)
	}
	return w.next.Login(ctx, req)
}

// ValidateSession asks root first; tokens are random, so they never collide.
func (w withRoot) ValidateSession(ctx context.Context, token string) (Session, error) {
	if s, err := w.root.ValidateSession(ctx, token); err == nil {
		return s, nil
	}
	return w.next.ValidateSession(ctx, token)
}

// Logout revokes token wherever it lives.
func (w withRoot) Logout(ctx context.Context, token string) error {
	if err := w.root.Logout(ctx, token); err != nil {
		return err
	}
	return w.next.Logout(ctx, token)
}
