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

// CreateLoginProfile implements Admin: it gives user a console password.
func (f *Fake) CreateLoginProfile(_ context.Context, a resource.AccountID, user, password string) (LoginProfile, error) {
	if err := checkPassword(password); err != nil {
		return LoginProfile{}, err
	}
	hash, err := hashPassword(password)
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
func (f *Fake) UpdateLoginProfile(_ context.Context, a resource.AccountID, user, password string) error {
	if err := checkPassword(password); err != nil {
		return err
	}
	hash, err := hashPassword(password)
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
	delete(f.lockouts, lockKey(a, user))
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
	delete(f.lockouts, lockKey(a, user))
	return nil
}

func (st *store) user(name string) *userRec {
	if st == nil {
		return nil
	}
	return st.users[name]
}

func lockKey(a resource.AccountID, user string) string { return a.String() + "/" + user }

// --- sign-in (Sessions) ---

// Login implements Sessions. Every failure is the same Unauthenticated error
// and costs one argon2id verification, so it reveals neither whether the user
// exists nor which field was wrong. MaxLoginFailures in a row lock the user
// for LockoutPeriod. Users have no MFA devices yet (vws-iam#6), so any MFA
// code fails.
func (f *Fake) Login(_ context.Context, req LoginRequest) (Session, error) {
	now := f.now()
	f.mu.RLock()
	u := f.accounts[req.Account].user(req.UserName)
	hash, p := f.dummy(), Principal{}
	if u != nil && u.login != nil {
		hash, p = u.login.hash, Principal{Account: req.Account, ARN: u.ARN}
	}
	f.mu.RUnlock()
	key := lockKey(req.Account, req.UserName)
	match := verifyPassword(hash, req.Password)
	if p.ARN == "" {
		return Session{}, errLogin()
	}
	f.mu.Lock()
	l := f.lockouts[key]
	if l != nil && now.Before(l.until) {
		f.mu.Unlock()
		return Session{}, errLogin()
	}
	if !match || req.MFACode != "" {
		if l == nil {
			l = &lockout{}
			f.lockouts[key] = l
		}
		l.failures++
		if l.failures >= MaxLoginFailures {
			l.failures, l.until = 0, now.Add(LockoutPeriod)
		}
		f.mu.Unlock()
		return Session{}, errLogin()
	}
	delete(f.lockouts, key)
	f.mu.Unlock()
	return f.sessions.open(p, now)
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
func (s *Static) SetPassword(password string) error {
	if err := checkPassword(password); err != nil {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.password, s.lock = hash, lockout{}
	return nil
}

func (s *Static) isRoot(req LoginRequest) bool {
	return req.UserName == RootUserName && req.Account == s.key.Principal.Account
}

// Login implements Sessions for the account root, with the same lockout and
// uniform failure as IAM users. Root has no MFA device here either.
func (s *Static) Login(_ context.Context, req LoginRequest) (Session, error) {
	now := time.Now()
	s.mu.Lock()
	hash := s.password
	locked := now.Before(s.lock.until)
	s.mu.Unlock()
	if hash == "" || !s.isRoot(req) {
		_ = verifyPassword(s.dummy(), req.Password)
		return Session{}, errLogin()
	}
	match := verifyPassword(hash, req.Password) && req.MFACode == ""
	s.mu.Lock()
	defer s.mu.Unlock()
	if locked {
		return Session{}, errLogin()
	}
	if !match {
		s.lock.failures++
		if s.lock.failures >= MaxLoginFailures {
			s.lock = lockout{until: now.Add(LockoutPeriod)}
		}
		return Session{}, errLogin()
	}
	s.lock = lockout{}
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
