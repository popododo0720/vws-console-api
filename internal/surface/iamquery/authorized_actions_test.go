package iamquery

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// boundMover moves the user, group or role it names to /denied/ right after
// the surface's first lookup of it, which is the lookup the surface
// authorizes on. A role cannot change its path, so it is deleted and created
// again on /denied/.
type boundMover struct {
	iam.Directory
	tb                testing.TB
	user, group, role string
	moved             bool
}

func (a *boundMover) ResolveUser(ctx context.Context, account resource.AccountID, name string) (iam.Ref, error) {
	u, err := a.Directory.ResolveUser(ctx, account, name)
	if err == nil && !a.moved && name == a.user {
		a.moved = true
		if err := a.UpdateUser(ctx, account, name, "/denied/", "", backendtest.Grant(ctx, a.tb, u.ARN)); err != nil {
			return iam.Ref{}, err
		}
	}
	return u, err
}

func (a *boundMover) ResolveGroup(ctx context.Context, account resource.AccountID, name string) (iam.Ref, error) {
	g, err := a.Directory.ResolveGroup(ctx, account, name)
	if err == nil && !a.moved && name == a.group {
		a.moved = true
		if err := a.UpdateGroup(ctx, account, name, "/denied/", "", backendtest.Grant(ctx, a.tb, g.ARN)); err != nil {
			return iam.Ref{}, err
		}
	}
	return g, err
}

func (a *boundMover) ResolveRole(ctx context.Context, account resource.AccountID, name string) (iam.Ref, error) {
	ref, err := a.Directory.ResolveRole(ctx, account, name)
	if err == nil && !a.moved && name == a.role {
		a.moved = true
		r, err := a.GetRole(ctx, account, name, backendtest.Grant(ctx, a.tb, ref.ARN))
		if err != nil {
			return iam.Ref{}, err
		}
		if err := a.DeleteRole(ctx, account, name, backendtest.Grant(ctx, a.tb, r.ARN)); err != nil {
			return iam.Ref{}, err
		}
		in := iam.RoleInput{Name: name, Path: "/denied/", TrustPolicy: r.TrustPolicy}
		if _, err := a.CreateRole(ctx, account, in); err != nil {
			return iam.Ref{}, err
		}
	}
	return ref, err
}

const boundTrustPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Principal":{"Service":"compute.vws"},"Action":"sts:AssumeRole"}]}`

// #342 (#331): every IAM action bound to an AuthorizedARN answers a user,
// group or role that moved to a path the caller is denied between the
// authorization and the call with 409 ConcurrentModification and no data.
// Without the move the same request succeeds, so the policy allows it. The
// backend contract (backendtest.IAMAuthorizedARN) shows that nothing is
// written.
func TestEveryBoundActionActsOnTheAuthorizedARN(t *testing.T) {
	doc := url.QueryEscape(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
	)
	doc, _ = url.QueryUnescape(doc)
	p1 := "arn:vws:iam::123456789012:policy/P1"
	p2 := "arn:vws:iam::123456789012:policy/P2"
	for _, tc := range []struct {
		form              url.Values
		user, group, role string
		secret            string // response text that must not leak after a move
	}{
		{url.Values{"Action": {"GetUser"}, "UserName": {"erin"}}, "erin", "", "", "<UserName>erin"},
		{
			url.Values{"Action": {"CreateLoginProfile"}, "UserName": {"dave"}, "Password": {"correct horse battery 7"}},
			"dave", "", "", "<UserName>dave",
		},
		{url.Values{"Action": {"GetLoginProfile"}, "UserName": {"erin"}}, "erin", "", "", "<UserName>erin"},
		{
			url.Values{"Action": {"UpdateLoginProfile"}, "UserName": {"erin"}, "Password": {"another horse battery 8"}},
			"erin", "", "", "",
		},
		{url.Values{"Action": {"DeleteLoginProfile"}, "UserName": {"erin"}}, "erin", "", "", ""},
		{url.Values{"Action": {"ListGroupsForUser"}, "UserName": {"erin"}}, "erin", "", "", "<GroupName>"},
		{url.Values{"Action": {"AttachUserPolicy"}, "UserName": {"erin"}, "PolicyArn": {p1}}, "erin", "", "", ""},
		{
			url.Values{"Action": {"DetachUserPolicy"}, "UserName": {"erin"}, "PolicyArn": {p2}},
			"erin", "", "", "",
		},
		{url.Values{"Action": {"ListAttachedUserPolicies"}, "UserName": {"erin"}}, "erin", "", "", "<PolicyName>"},
		{
			url.Values{"Action": {"PutUserPolicy"}, "UserName": {"erin"}, "PolicyName": {"new"}, "PolicyDocument": {doc}},
			"erin", "", "", "",
		},
		{
			url.Values{"Action": {"GetUserPolicy"}, "UserName": {"erin"}, "PolicyName": {"inline"}},
			"erin", "", "", "<PolicyDocument>",
		},
		{url.Values{"Action": {"DeleteUserPolicy"}, "UserName": {"erin"}, "PolicyName": {"inline"}}, "erin", "", "", ""},
		{url.Values{"Action": {"ListUserPolicies"}, "UserName": {"erin"}}, "erin", "", "", "<member>"},
		{url.Values{"Action": {"GetGroup"}, "GroupName": {"mover"}}, "", "mover", "", "<GroupName>mover"},
		{url.Values{"Action": {"AttachGroupPolicy"}, "GroupName": {"mover"}, "PolicyArn": {p1}}, "", "mover", "", ""},
		{
			url.Values{"Action": {"DetachGroupPolicy"}, "GroupName": {"mover"}, "PolicyArn": {p2}},
			"", "mover", "", "",
		},
		{url.Values{"Action": {"ListAttachedGroupPolicies"}, "GroupName": {"mover"}}, "", "mover", "", "<PolicyName>"},
		{
			url.Values{"Action": {"PutGroupPolicy"}, "GroupName": {"mover"}, "PolicyName": {"new"}, "PolicyDocument": {doc}},
			"", "mover", "", "",
		},
		{
			url.Values{"Action": {"GetGroupPolicy"}, "GroupName": {"mover"}, "PolicyName": {"inline"}},
			"", "mover", "", "<PolicyDocument>",
		},
		{url.Values{"Action": {"DeleteGroupPolicy"}, "GroupName": {"mover"}, "PolicyName": {"inline"}}, "", "mover", "", ""},
		{url.Values{"Action": {"ListGroupPolicies"}, "GroupName": {"mover"}}, "", "mover", "", "<member>"},
		{url.Values{"Action": {"GetRole"}, "RoleName": {"ops"}}, "", "", "ops", "<RoleName>ops"},
		{url.Values{"Action": {"UpdateRole"}, "RoleName": {"ops"}, "Description": {"new"}}, "", "", "ops", ""},
		{
			url.Values{"Action": {"UpdateRoleDescription"}, "RoleName": {"ops"}, "Description": {"new"}},
			"", "", "ops", "<RoleName>ops",
		},
		{
			url.Values{"Action": {"UpdateAssumeRolePolicy"}, "RoleName": {"ops"}, "PolicyDocument": {boundTrustPolicy}},
			"", "", "ops", "",
		},
		{url.Values{"Action": {"DeleteRole"}, "RoleName": {"ops"}}, "", "", "ops", ""},
		{url.Values{"Action": {"AttachRolePolicy"}, "RoleName": {"ops"}, "PolicyArn": {p1}}, "", "", "ops", ""},
		{
			url.Values{"Action": {"PutRolePolicy"}, "RoleName": {"ops"}, "PolicyName": {"new"}, "PolicyDocument": {doc}},
			"", "", "ops", "",
		},
		{url.Values{"Action": {"ListAttachedRolePolicies"}, "RoleName": {"ops"}}, "", "", "ops", ""},
		{url.Values{"Action": {"ListRolePolicies"}, "RoleName": {"ops"}}, "", "", "ops", ""},
	} {
		name := tc.form.Get("Action")
		t.Run(name+"/not moved", func(t *testing.T) {
			h, bob := boundActionHarness(t, nil)
			has(t, call(t, h, bob, sigv4.ServiceIAM, cloneForm(tc.form)), http.StatusOK)
		})
		t.Run(name+"/moved after authorization", func(t *testing.T) {
			h, bob := boundActionHarness(t, &boundMover{tb: t, user: tc.user, group: tc.group, role: tc.role})
			res := call(t, h, bob, sigv4.ServiceIAM, cloneForm(tc.form))
			has(t, res, http.StatusConflict, "<Code>ConcurrentModification</Code>")
			if tc.secret != "" && strings.Contains(res.Body.String(), tc.secret) {
				t.Errorf("data of a moved entity in the answer: %s", res.Body.String())
			}
		})
	}
}

func cloneForm(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// boundActionHarness seeds users dave and erin and group mover on /ok/ and
// role ops on /ok/, the managed policies P1 and P2 with P2 attached to erin
// and mover, the inline policy "inline" on erin and mover, a console password
// for erin and erin's membership of mover. The caller bob may do anything to
// users, groups and roles on /ok/ and nothing on /denied/.
func boundActionHarness(t *testing.T, mover *boundMover) (http.Handler, sigv4.Credential) {
	t.Helper()
	h, f, _, root := harnessWith(t, func(a iam.Directory) iam.Directory {
		if mover == nil {
			return a
		}
		mover.Directory = a
		return mover
	})
	ctx, acct := t.Context(), root.Account
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []string{"dave", "erin"} {
		_, err := f.CreateUser(ctx, acct, u, "/ok/")
		must(err)
	}
	_, err := f.CreateUser(ctx, acct, "bob", "/")
	must(err)
	_, err = f.CreateGroup(ctx, acct, "mover", "/ok/")
	must(err)
	_, err = f.CreateRole(ctx, acct, iam.RoleInput{Name: "ops", Path: "/ok/", TrustPolicy: boundTrustPolicy})
	must(err)
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	for _, p := range []string{"P1", "P2"} {
		_, err := f.CreatePolicy(ctx, acct, p, "/", doc, "")
		must(err)
	}
	p2 := "arn:vws:iam::" + acct.String() + ":policy/P2"
	erin := backendtest.UserGrant(ctx, t, f, acct, "erin")
	movers := backendtest.GroupGrant(ctx, t, f, acct, "mover")
	must(f.AttachPolicy(ctx, acct, iam.EntityUser, "erin", p2, erin))
	must(f.AttachPolicy(ctx, acct, iam.EntityGroup, "mover", p2, movers))
	must(f.PutInlinePolicy(ctx, acct, iam.EntityUser, "erin", "inline", doc, erin))
	must(f.PutInlinePolicy(ctx, acct, iam.EntityGroup, "mover", "inline", doc, movers))
	_, err = f.CreateLoginProfile(ctx, acct, "erin", "correct horse battery 7", erin)
	must(err)
	must(f.AddUserToGroup(ctx, acct, "mover", "erin", movers))
	arn := "arn:vws:iam::" + acct.String() + ":"
	policy := `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":"iam:*","Resource":["` +
		arn + `group/ok/*","` + arn + `user/ok/*","` + arn + `role/ok/*"]},` +
		`{"Effect":"Deny","Action":"iam:*","Resource":["` +
		arn + `group/denied/*","` + arn + `user/denied/*","` + arn + `role/denied/*"]}]}`
	must(f.PutInlinePolicy(ctx, acct, iam.EntityUser, "bob", "ok", policy, backendtest.UserGrant(ctx, t, f, acct, "bob")))
	key, err := f.CreateAccessKey(ctx, acct, "bob", backendtest.UserGrant(ctx, t, f, acct, "bob"))
	must(err)
	return h, sigv4.Credential{AccessKey: key.AccessKeyID, Secret: key.Secret}
}
