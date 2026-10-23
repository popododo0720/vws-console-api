package iamquery

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// movingAdmin moves one group or user to /denied/ right after the surface's
// first lookup of it. A concurrent UpdateGroup or UpdateUser does the same
// between the authorization and the change.
type movingAdmin struct {
	iam.Admin
	tb          testing.TB
	group, user string
	moved       bool
}

func (a *movingAdmin) GetGroup(
	ctx context.Context, account resource.AccountID, name string,
) (iam.Group, []iam.User, error) {
	g, us, err := a.Admin.GetGroup(ctx, account, name)
	if err == nil && !a.moved && name == a.group {
		a.moved = true
		if err := a.UpdateGroup(
			ctx, account, name, "/denied/", "", backendtest.GroupGrant(ctx, a.tb, a, account, name),
		); err != nil {
			return iam.Group{}, nil, err
		}
	}
	return g, us, err
}

func (a *movingAdmin) GetUser(ctx context.Context, account resource.AccountID, name string) (iam.User, error) {
	u, err := a.Admin.GetUser(ctx, account, name)
	if err == nil && !a.moved && name == a.user {
		a.moved = true
		if err := a.UpdateUser(
			ctx, account, name, "/denied/", "", backendtest.UserGrant(ctx, a.tb, a, account, name),
		); err != nil {
			return iam.User{}, err
		}
	}
	return u, err
}

// #325 r1: a group or user change acts only on the entity the caller was
// authorized on. When the entity moves to a denied path between the
// authorization and the change, the answer is 409 ConcurrentModification and
// nothing changes. Without the move the same requests succeed, so the policy
// allows them.
func TestGroupAndUserChangesActOnTheAuthorizedARN(t *testing.T) {
	type state struct {
		f       *iam.Fake
		account resource.AccountID
	}
	for _, tc := range []struct {
		name        string
		form        url.Values
		group, user string // the entity that moves
		unchanged   func(t *testing.T, s state)
	}{
		{
			"AddUserToGroup",
			url.Values{"Action": {"AddUserToGroup"}, "GroupName": {"devs"}, "UserName": {"dave"}},
			"devs", "", func(t *testing.T, s state) { t.Helper(); members(t, s.f, s.account, "devs", "carol") },
		},
		{
			"RemoveUserFromGroup",
			url.Values{"Action": {"RemoveUserFromGroup"}, "GroupName": {"devs"}, "UserName": {"carol"}},
			"devs", "", func(t *testing.T, s state) { t.Helper(); members(t, s.f, s.account, "devs", "carol") },
		},
		{
			"DeleteGroup",
			url.Values{"Action": {"DeleteGroup"}, "GroupName": {"empty"}},
			"empty", "", func(t *testing.T, s state) {
				t.Helper()
				if _, _, err := s.f.GetGroup(t.Context(), s.account, "empty"); err != nil {
					t.Errorf("the group was deleted: %v", err)
				}
			},
		},
		{
			"UpdateGroup",
			url.Values{"Action": {"UpdateGroup"}, "GroupName": {"mover"}, "NewPath": {"/ok/x/"}},
			"mover", "", func(t *testing.T, s state) {
				t.Helper()
				if g, _, err := s.f.GetGroup(t.Context(), s.account, "mover"); err != nil || g.Path != "/denied/" {
					t.Errorf("the group moved to %+v: %v", g, err)
				}
			},
		},
		{
			"DeleteUser",
			url.Values{"Action": {"DeleteUser"}, "UserName": {"erin"}},
			"", "erin", func(t *testing.T, s state) {
				t.Helper()
				if _, err := s.f.GetUser(t.Context(), s.account, "erin"); err != nil {
					t.Errorf("the user was deleted: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name+"/not moved", func(t *testing.T) {
			h, _, _, bob := authorizedARNHarness(t, nil)
			has(t, call(t, h, bob, sigv4.ServiceIAM, tc.form), http.StatusOK)
		})
		t.Run(tc.name+"/moved after authorization", func(t *testing.T) {
			h, f, account, bob := authorizedARNHarness(t, &movingAdmin{tb: t, group: tc.group, user: tc.user})
			res := call(t, h, bob, sigv4.ServiceIAM, tc.form)
			has(t, res, http.StatusConflict, "<Code>ConcurrentModification</Code>")
			tc.unchanged(t, state{f, account})
		})
	}
}

// authorizedARNHarness seeds groups devs (member carol), empty and mover and
// users carol, dave and erin, all on /ok/. The caller bob may change
// anything on /ok/ and nothing on /denied/. A non-nil mover wraps the Admin
// the surface calls.
func authorizedARNHarness(
	t *testing.T, mover *movingAdmin,
) (http.Handler, *iam.Fake, resource.AccountID, sigv4.Credential) {
	t.Helper()
	h, f, _, root := harnessWith(t, func(a iam.Admin) iam.Admin {
		if mover == nil {
			return a
		}
		mover.Admin = a
		return mover
	})
	ctx := t.Context()
	for _, u := range []string{"bob", "carol", "dave", "erin"} {
		path := "/ok/"
		if u == "bob" {
			path = "/"
		}
		if _, err := f.CreateUser(ctx, root.Account, u, path); err != nil {
			t.Fatal(err)
		}
	}
	for _, g := range []string{"devs", "empty", "mover"} {
		if _, err := f.CreateGroup(ctx, root.Account, g, "/ok/"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.AddUserToGroup(
		ctx, root.Account, "devs", "carol", backendtest.GroupGrant(ctx, t, f, root.Account, "devs"),
	); err != nil {
		t.Fatal(err)
	}
	arn := "arn:vws:iam::" + root.Account.String() + ":"
	policy := `{"Statement":[` +
		`{"Effect":"Allow","Action":"iam:*","Resource":["` + arn + `group/ok/*","` + arn + `user/ok/*"]},` +
		`{"Effect":"Deny","Action":"iam:*","Resource":["` + arn + `group/denied/*","` + arn + `user/denied/*"]}]}`
	if err := f.PutInlinePolicy(
		ctx,
		root.Account,
		iam.EntityUser,
		"bob",
		"ok",
		policy,
		backendtest.EntityGrant(ctx, t, f, root.Account, iam.EntityUser, "bob"),
	); err != nil {
		t.Fatal(err)
	}
	key, err := f.CreateAccessKey(ctx, root.Account, "bob", backendtest.UserGrant(ctx, t, f, root.Account, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	return h, f, root.Account, sigv4.Credential{AccessKey: key.AccessKeyID, Secret: key.Secret}
}

func members(t *testing.T, f *iam.Fake, account resource.AccountID, group string, want ...string) {
	t.Helper()
	_, us, err := f.GetGroup(t.Context(), account, group)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, u := range us {
		got = append(got, u.Name)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("members of %s are %s, want %s", group, strings.Join(got, ","), strings.Join(want, ","))
	}
}
