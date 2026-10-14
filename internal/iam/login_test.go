package iam

import (
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
	if _, err := f.CreateLoginProfile(t.Context(), a, "bob", "correct horse 1"); err != nil {
		t.Fatal(err)
	}
	return f, a
}

func TestLoginProfiles(t *testing.T) {
	ctx := t.Context()
	f, a := loginFake(t)
	if _, err := f.CreateLoginProfile(ctx, a, "bob", "another pass 2"); resource.CodeOf(err) != resource.CodeAlreadyExists {
		t.Errorf("second profile: %v", err)
	}
	if _, err := f.CreateUser(ctx, a, "eve", "/"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateLoginProfile(ctx, a, "eve", "short"); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("weak password: %v", err)
	}
	if _, err := f.CreateLoginProfile(ctx, a, "nobody", "correct horse 1"); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing user: %v", err)
	}
	p, err := f.GetLoginProfile(ctx, a, "bob")
	if err != nil || p.UserName != "bob" || !p.Created.Equal(now) {
		t.Fatalf("get profile %+v %v", p, err)
	}
	if err := f.DeleteUser(ctx, a, "bob"); resource.CodeOf(err) != resource.CodeConflict {
		t.Errorf("delete user with a login profile: %v", err)
	}
	must(t, f.UpdateLoginProfile(ctx, a, "bob", "brand new pass 3"))
	if _, err := f.Login(ctx, LoginRequest{Account: a, UserName: "bob", Password: "correct horse 1"}); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("old password still works: %v", err)
	}
	if _, err := f.Login(ctx, LoginRequest{Account: a, UserName: "bob", Password: "brand new pass 3"}); err != nil {
		t.Errorf("new password: %v", err)
	}
	must(t, f.DeleteLoginProfile(ctx, a, "bob"))
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

func TestLoginLockout(t *testing.T) {
	ctx := t.Context()
	f, a := loginFake(t)
	for range MaxLoginFailures {
		if _, err := f.Login(ctx, LoginRequest{Account: a, UserName: "bob", Password: "guess"}); resource.CodeOf(err) != resource.CodeUnauthenticated {
			t.Fatal(err)
		}
	}
	if _, err := f.Login(ctx, LoginRequest{Account: a, UserName: "bob", Password: "correct horse 1"}); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Fatalf("locked account accepted the right password: %v", err)
	}
	f.Now = func() time.Time { return now.Add(LockoutPeriod) }
	if _, err := f.Login(ctx, LoginRequest{Account: a, UserName: "bob", Password: "correct horse 1"}); err != nil {
		t.Fatalf("after the lockout period: %v", err)
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
	must(t, root.SetPassword("root password 9"))
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
