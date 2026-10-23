package iam

import (
	"bytes"
	"log/slog"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func loginFake(t *testing.T) (*Fake, resource.AccountID) {
	t.Helper()
	f := NewFake()
	f.Now = func() time.Time { return now }
	a := account(t)
	if _, err := f.CreateUser(t.Context(), a, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateLoginProfile(
		t.Context(), a, "bob", "correct horse 1", testUserGrant(t.Context(), t, f, a, "bob"),
	); err != nil {
		t.Fatal(err)
	}
	return f, a
}

func TestLoginProfiles(t *testing.T) {
	ctx := t.Context()
	f, a := loginFake(t)
	if _, err := f.CreateLoginProfile(
		ctx, a, "bob", "another pass 2", testUserGrant(ctx, t, f, a, "bob"),
	); resource.CodeOf(err) != resource.CodeAlreadyExists {
		t.Errorf("second profile: %v", err)
	}
	if _, err := f.CreateUser(ctx, a, "eve", "/"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateLoginProfile(
		ctx, a, "eve", "short", testUserGrant(ctx, t, f, a, "eve"),
	); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("weak password: %v", err)
	}
	if _, err := f.CreateLoginProfile(
		ctx, a, "nobody", "correct horse 1", testUserGrant(ctx, t, f, a, "nobody"),
	); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing user: %v", err)
	}
	p, err := f.GetLoginProfile(ctx, a, "bob", testUserGrant(ctx, t, f, a, "bob"))
	if err != nil || p.UserName != "bob" || !p.Created.Equal(now) {
		t.Fatalf("get profile %+v %v", p, err)
	}
	if err := f.DeleteUser(
		ctx, a, "bob", testUserGrant(ctx, t, f, a, "bob"),
	); resource.CodeOf(err) != resource.CodeConflict {
		t.Errorf("delete user with a login profile: %v", err)
	}
	must(t, f.UpdateLoginProfile(ctx, a, "bob", "brand new pass 3", testUserGrant(ctx, t, f, a, "bob")))
	if _, err := f.Login(ctx, LoginRequest{Account: a, UserName: "bob", Password: "correct horse 1"}); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("old password still works: %v", err)
	}
	if _, err := f.Login(ctx, LoginRequest{Account: a, UserName: "bob", Password: "brand new pass 3"}); err != nil {
		t.Errorf("new password: %v", err)
	}
	must(t, f.DeleteLoginProfile(ctx, a, "bob", testUserGrant(ctx, t, f, a, "bob")))
	if _, err := f.Login(ctx, LoginRequest{Account: a, UserName: "bob", Password: "brand new pass 3"}); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("login without a profile: %v", err)
	}
	f.mu.RLock()
	for _, st := range f.accounts {
		for _, u := range st.users {
			if u.login != nil && (strings.Contains(u.login.hash, "pass") || !strings.HasPrefix(u.login.hash, "$argon2id$v=19$")) {
				t.Errorf("password not stored as an argon2id hash: %q", u.login.hash)
			}
		}
	}
	f.mu.RUnlock()
}

func TestLoginSessions(t *testing.T) {
	ctx := t.Context()
	f, a := loginFake(t)
	s, err := f.Login(ctx, LoginRequest{Account: a, UserName: "bob", Password: "correct horse 1", SourceIP: "192.0.2.1"})
	if err != nil || len(s.Token) < 40 || s.Principal.ARN != "arn:vws:iam::123456789012:user/bob" || !s.Expires.Equal(now.Add(SessionTTL)) {
		t.Fatalf("login %+v %v", s, err)
	}
	got, err := f.ValidateSession(ctx, s.Token)
	if err != nil || got.Principal != s.Principal || got.Token != "" {
		t.Fatalf("validate %+v %v", got, err)
	}
	same := ""
	for _, bad := range []LoginRequest{
		{Account: a, UserName: "bob", Password: "wrong"},
		{Account: a, UserName: "nobody", Password: "correct horse 1"},
		{Account: a, UserName: "bob", Password: "correct horse 1", MFACode: "123456"},
	} {
		_, err := f.Login(ctx, bad)
		e := resource.AsError(err)
		if e == nil || e.Code != resource.CodeUnauthenticated {
			t.Fatalf("%+v: %v", bad, err)
		}
		if same == "" {
			same = e.Message
		} else if e.Message != same {
			t.Errorf("failure messages differ (%q, %q): they would reveal which part was wrong", same, e.Message)
		}
	}
	must(t, f.Logout(ctx, s.Token))
	if _, err := f.ValidateSession(ctx, s.Token); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("session after logout: %v", err)
	}
	s2, err := f.Login(ctx, LoginRequest{Account: a, UserName: "bob", Password: "correct horse 1"})
	if err != nil {
		t.Fatal(err)
	}
	f.Now = func() time.Time { return now.Add(SessionTTL) }
	if _, err := f.ValidateSession(ctx, s2.Token); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("expired session: %v", err)
	}
	if _, err := f.ValidateSession(ctx, "not-a-token"); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("unknown token: %v", err)
	}
}

func TestLoginLockoutIsPerUserAndIPWithBackoff(t *testing.T) {
	ctx := t.Context()
	f, a := loginFake(t)
	var logs bytes.Buffer
	f.SetLogger(slog.New(slog.NewJSONHandler(&logs, nil)))
	clock := now
	f.Now = func() time.Time { return clock }
	try := func(ip, pw string) error {
		_, err := f.Login(ctx, LoginRequest{Account: a, UserName: "bob", Password: pw, SourceIP: ip})
		return err
	}
	for range MaxLoginFailures {
		if err := try("198.51.100.1", "guess wrong 1"); resource.CodeOf(err) != resource.CodeUnauthenticated {
			t.Fatal(err)
		}
	}
	if err := try("198.51.100.1", "correct horse 1"); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Fatalf("locked user+IP accepted the right password: %v", err)
	}
	// The attacker's lockout does not lock bob out from his own address.
	if err := try("192.0.2.50", "correct horse 1"); err != nil {
		t.Fatalf("bob from another IP: %v", err)
	}
	if !strings.Contains(logs.String(), `"msg":"console sign-in locked out"`) || !strings.Contains(logs.String(), `"source_ip":"198.51.100.1"`) || !strings.Contains(logs.String(), `"user":"bob"`) {
		t.Errorf("no lockout notice: %s", logs.String())
	}
	if strings.Contains(logs.String(), "guess wrong") || strings.Contains(logs.String(), "correct horse") {
		t.Errorf("password in the log: %s", logs.String())
	}
	// Backoff: the first lock lasts LockoutBase, the next one twice that.
	clock = clock.Add(LockoutBase)
	if err := try("198.51.100.1", "guess wrong 1"); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Fatal(err)
	}
	clock = clock.Add(LockoutBase)
	if err := try("198.51.100.1", "correct horse 1"); err == nil {
		t.Fatal("second lock should last 2x LockoutBase")
	}
	clock = clock.Add(LockoutBase)
	if err := try("198.51.100.1", "correct horse 1"); err != nil {
		t.Fatalf("after 2x LockoutBase: %v", err)
	}
	// Success clears the count: the next failure does not lock at once.
	if err := try("198.51.100.1", "guess wrong 1"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if err := try("198.51.100.1", "correct horse 1"); err != nil {
		t.Fatalf("one failure after a success locked: %v", err)
	}
	if d := lockFor(MaxLoginFailures + 40); d != LockoutMax {
		t.Errorf("backoff not capped: %v", d)
	}
}

func TestRootCannotBeLockedOutFromAnotherIP(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	root := NewStatic("AKIDEXAMPLE", "secret", a)
	must(t, root.SetPassword(t.Context(), "root password 9"))
	for range MaxLoginFailures + 3 {
		_, _ = root.Login(ctx, LoginRequest{Account: a, UserName: RootUserName, Password: "nope nope 1", SourceIP: "203.0.113.9"})
	}
	if _, err := root.Login(ctx, LoginRequest{Account: a, UserName: RootUserName, Password: "root password 9", SourceIP: "203.0.113.9"}); err == nil {
		t.Error("attacker IP not locked")
	}
	if _, err := root.Login(ctx, LoginRequest{Account: a, UserName: RootUserName, Password: "root password 9", SourceIP: "192.0.2.1"}); err != nil {
		t.Errorf("root locked out from its own IP: %v", err)
	}
}

func TestHashingIsBounded(t *testing.T) {
	ctx := t.Context()
	f, a := loginFake(t)
	f.LimitHashing(1)
	f.guard.slots <- struct{}{} // the one slot is busy
	_, err := f.Login(ctx, LoginRequest{Account: a, UserName: "bob", Password: "correct horse 1", SourceIP: "192.0.2.1"})
	if resource.CodeOf(err) != resource.CodeUnavailable || !IsBusy(err) {
		t.Fatalf("full hashing slots: %v", err)
	}
	if _, err := f.CreateLoginProfile(
		ctx, a, "bob", "x long enough 1", testUserGrant(ctx, t, f, a, "bob"),
	); !IsBusy(err) && resource.CodeOf(err) != resource.CodeAlreadyExists {
		t.Fatalf("profile hashing while full: %v", err)
	}
	<-f.guard.slots
	if _, err := f.Login(ctx, LoginRequest{Account: a, UserName: "bob", Password: "correct horse 1", SourceIP: "192.0.2.1"}); err != nil {
		t.Fatalf("after the slot frees: %v", err)
	}
	root := NewStatic("AKIDEXAMPLE", "secret", a)
	must(t, root.SetPassword(t.Context(), "root password 9"))
	root.LimitHashing(1)
	root.guard.slots <- struct{}{}
	if _, err := root.Login(ctx, LoginRequest{Account: a, UserName: RootUserName, Password: "root password 9"}); !IsBusy(err) {
		t.Fatalf("root while full: %v", err)
	}
}

func TestRootLoginThroughWithRoot(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	root := NewStatic("AKIDEXAMPLE", "secret", a)
	f := NewFake()
	c := WithRoot(root, f)
	if _, err := c.Login(ctx, LoginRequest{Account: a, UserName: RootUserName, Password: "anything"}); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Fatalf("root login without a password set: %v", err)
	}
	must(t, root.SetPassword(t.Context(), "root password 9"))
	s, err := c.Login(ctx, LoginRequest{Account: a, UserName: RootUserName, Password: "root password 9"})
	if err != nil || !s.Principal.Root || s.Principal.ARN != RootARN(a) {
		t.Fatalf("root login %+v %v", s, err)
	}
	if got, err := c.ValidateSession(ctx, s.Token); err != nil || !got.Principal.Root {
		t.Fatalf("root session %+v %v", got, err)
	}
	must(t, c.Logout(ctx, s.Token))
	if _, err := c.ValidateSession(ctx, s.Token); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("root session after logout: %v", err)
	}
	if _, err := f.CreateUser(ctx, a, RootUserName, "/"); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("a user named %q would shadow root: %v", RootUserName, err)
	}
}

// loginWhileHashing runs a login and calls during after the password hash
// starts. The login cannot open a session until during returns and guard.mu is
// released. The test fails if the hash always finishes first.
func loginWhileHashing(t *testing.T, f *Fake, req LoginRequest, during func()) (Session, error) {
	t.Helper()
	type result struct {
		session Session
		err     error
	}
	for range 20 {
		done := make(chan result, 1)
		go func() {
			s, err := f.Login(t.Context(), req)
			done <- result{s, err}
		}()
		// Wait until the login holds the hash slot. It has read the user and
		// cannot open the session until the hash returns.
		for len(f.guard.slots) == 0 {
			runtime.Gosched()
		}
		f.guard.mu.Lock()
		if len(f.guard.slots) != 1 {
			// The hash finished before the lock. Discard this attempt.
			f.guard.mu.Unlock()
			<-done
			continue
		}
		during()
		f.guard.mu.Unlock()
		got := <-done
		return got.session, got.err
	}
	t.Fatal("login never paused while hashing")
	return Session{}, nil
}

// TestLoginDuringRenameUsesTheNewARN holds a login after it reads the old ARN
// and moves the user before the session opens. The session must name the new
// ARN, never the one the login snapshot held.
func TestLoginDuringRenameUsesTheNewARN(t *testing.T) {
	ctx := t.Context()
	f, a := loginFake(t)
	f.LimitHashing(1)
	var updateErr error
	s, err := loginWhileHashing(t, f, LoginRequest{
		Account: a, UserName: "bob", Password: "correct horse 1", SourceIP: "192.0.2.1",
	}, func() {
		updateErr = f.UpdateUser(ctx, a, "bob", "/new/", "", testUserGrant(ctx, t, f, a, "bob"))
	})
	if updateErr != nil {
		t.Fatal(updateErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.ValidateSession(ctx, s.Token)
	if err != nil {
		t.Fatal(err)
	}
	if got.Principal.ARN != "arn:vws:iam::123456789012:user/new/bob" {
		t.Errorf("session opened with %s during a rename, want the new ARN", got.Principal.ARN)
	}
}

// TestLoginAfterPasswordChangeUsesTheVerifiedHash holds a login after it reads
// the old hash, changes the password, then lets the session open. The old
// password must not open a session for the updated profile.
func TestLoginAfterPasswordChangeUsesTheVerifiedHash(t *testing.T) {
	f, a := loginFake(t)
	f.LimitHashing(1)
	newHash, err := hashPassword("brand new pass 2")
	if err != nil {
		t.Fatal(err)
	}
	_, err = loginWhileHashing(t, f, LoginRequest{
		Account: a, UserName: "bob", Password: "correct horse 1", SourceIP: "192.0.2.1",
	}, func() {
		f.mu.Lock()
		f.accounts[a].users["bob"].login.hash = newHash
		f.mu.Unlock()
	})
	if resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Fatalf("old password opened a session after the profile changed: %v", err)
	}
}
