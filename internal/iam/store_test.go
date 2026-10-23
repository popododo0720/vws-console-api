package iam

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

const describeOnly = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:Describe*","sts:AssumeRole"],"Resource":"*"}]}`

func TestUsersGroupsAndPolicies(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	u, err := f.CreateUser(ctx, a, "bob", "/eng/")
	if err != nil || u.ARN != "arn:vws:iam::123456789012:user/eng/bob" || !strings.HasPrefix(u.ID, "AIDA") {
		t.Fatalf("create user %+v %v", u, err)
	}
	if _, err := f.CreateUser(ctx, a, "bob", "/"); resource.CodeOf(err) != resource.CodeAlreadyExists {
		t.Errorf("duplicate user: %v", err)
	}
	if _, err := f.CreateUser(ctx, a, "bad name!", "/"); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("bad name: %v", err)
	}
	other, _ := resource.Parse[resource.AccountID]("210987654321")
	if _, err := f.GetUser(ctx, other, "bob"); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("user visible from another account: %v", err)
	}
	if _, err := f.CreatePolicy(ctx, a, "bad", "/", `{"Statement":[{"Effect":"Maybe","Action":"*","Resource":"*"}]}`, ""); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("malformed policy: %v", err)
	}
	if _, err := f.CreatePolicy(ctx, a, "bad", "/", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`, ""); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("principal in an identity policy: %v", err)
	}
	p, err := f.CreatePolicy(ctx, a, "describe", "/", describeOnly, "")
	if err != nil || p.ARN != "arn:vws:iam::123456789012:policy/describe" {
		t.Fatalf("create policy %+v %v", p, err)
	}
	if _, err := f.CreateGroup(ctx, a, "readers", "/"); err != nil {
		t.Fatal(err)
	}
	must(t, f.AttachPolicy(ctx, a, EntityGroup, "readers", p.ARN))
	must(t, f.AddUserToGroup(ctx, a, "readers", "bob", ""))
	must(t, f.PutInlinePolicy(ctx, a, EntityUser, "bob", "deny-vols",
		`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"ec2:DescribeVolumes","Resource":"*"}}`))

	bob := Principal{Account: a, ARN: u.ARN}
	for _, tc := range []struct {
		action string
		want   bool
	}{
		{"ec2:DescribeVpcs", true},
		{"ec2:DescribeVolumes", false},
		{"ec2:RunInstances", false},
	} {
		if d, err := f.Authorize(ctx, Request{Principal: bob, Action: tc.action, Resource: "*"}); err != nil || d.Allowed != tc.want {
			t.Errorf("%s: %+v %v, want %v", tc.action, d, err, tc.want)
		}
	}
	if err := f.DeletePolicy(ctx, a, p.ARN); resource.CodeOf(err) != resource.CodeConflict {
		t.Errorf("delete attached policy: %v", err)
	}
	if err := f.DeleteUser(ctx, a, "bob", ""); resource.CodeOf(err) != resource.CodeConflict {
		t.Errorf("delete user in a group with a policy: %v", err)
	}
	must(t, f.RemoveUserFromGroup(ctx, a, "readers", "bob", ""))
	must(t, f.DeleteInlinePolicy(ctx, a, EntityUser, "bob", "deny-vols"))
	must(t, f.DeleteUser(ctx, a, "bob", ""))
	must(t, f.DetachPolicy(ctx, a, EntityGroup, "readers", p.ARN))
	must(t, f.DeletePolicy(ctx, a, p.ARN))
	must(t, f.DeleteGroup(ctx, a, "readers", ""))
}

func TestAccessKeysAuthenticate(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	f.Now = func() time.Time { return now }
	if _, err := f.CreateUser(ctx, a, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(ctx, a, "bob", "")
	if err != nil || !strings.HasPrefix(k.AccessKeyID, "AKIA") || len(k.AccessKeyID) != 20 || len(k.Secret) != 40 || k.Status != "Active" {
		t.Fatalf("create key %+v %v", k, err)
	}
	if c, err := verify(t, f, credOf(k.AccessKeyID, k.Secret, "")); err != nil || c.Principal != "arn:vws:iam::123456789012:user/bob" {
		t.Fatalf("new key: %+v %v", c, err)
	}
	keys, err := f.ListAccessKeys(ctx, a, "bob", "")
	if err != nil || len(keys) != 1 || keys[0].AccessKeyID != k.AccessKeyID {
		t.Fatalf("list keys %+v %v", keys, err)
	}
	must(t, f.DeleteAccessKey(ctx, a, "bob", k.AccessKeyID, ""))
	if _, err := verify(t, f, credOf(k.AccessKeyID, k.Secret, "")); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Fatalf("deleted key still works: %v", err)
	}
}

func TestGetAccessKeyLastUsed(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	f.Now = func() time.Time { return now }
	if _, err := f.CreateUser(ctx, a, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	used, err := f.CreateAccessKey(ctx, a, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := f.CreateAccessKey(ctx, a, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.GetAccessKeyLastUsed(ctx, a, fresh.AccessKeyID)
	if err != nil || got.UserName != "bob" || got.UserARN != "arn:vws:iam::123456789012:user/bob" ||
		!got.LastUsed.IsZero() || got.Service != "" || got.Region != "" {
		t.Fatalf("unused key %+v %v", got, err)
	}
	if _, err := verify(t, f, credOf(used.AccessKeyID, used.Secret, "")); err != nil {
		t.Fatal(err)
	}
	got, err = f.GetAccessKeyLastUsed(ctx, a, used.AccessKeyID)
	if err != nil || got.UserName != "bob" || !got.LastUsed.Equal(now) ||
		got.Service != string(sigv4.ServiceEC2) || got.Region != resource.RegionName {
		t.Fatalf("used key %+v %v", got, err)
	}
	if _, err := f.GetAccessKeyLastUsed(ctx, a, "AKIANOSUCHKEY0000000"); resource.CodeOf(err) != resource.CodeNotFound ||
		!strings.Contains(err.Error(), "cannot be found") {
		t.Fatalf("missing key: %v", err)
	}
}

func TestAssumeRole(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	f.Now = func() time.Time { return now }
	u, _ := f.CreateUser(ctx, a, "bob", "/")
	eve, _ := f.CreateUser(ctx, a, "eve", "/")
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"` + u.ARN + `"}}]}`
	if _, err := f.CreateRole(ctx, a, RoleInput{Name: "ops", Path: "/", TrustPolicy: `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole"}]}`}); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("trust policy without a principal: %v", err)
	}
	r, err := f.CreateRole(ctx, a, RoleInput{Name: "ops", Path: "/", TrustPolicy: trust})
	if err != nil || r.ARN != "arn:vws:iam::123456789012:role/ops" || r.MaxSessionDuration != 3600 {
		t.Fatalf("create role %+v %v", r, err)
	}
	must(t, f.PutInlinePolicy(ctx, a, EntityRole, "ops", "vpcs", `{"Statement":[{"Effect":"Allow","Action":"ec2:CreateVpc","Resource":"*"}]}`))

	got, err := f.AssumeRole(ctx, Principal{Account: a, ARN: u.ARN}, r.ARN, "s1", 15*time.Minute)
	if err != nil || !strings.HasPrefix(got.Key.AccessKey, "ASIA") || got.Key.SessionToken == "" || !got.Key.Expires.Equal(now.Add(15*time.Minute)) ||
		got.ARN != "arn:vws:sts::123456789012:assumed-role/ops/s1" || !strings.HasPrefix(got.AssumedRoleID, r.ID+":") {
		t.Fatalf("assume role %+v %v", got, err)
	}
	if c, err := verify(t, f, credOf(got.Key.AccessKey, got.Key.Secret, got.Key.SessionToken)); err != nil || c.Principal != got.ARN {
		t.Fatalf("temporary key: %+v %v", c, err)
	}
	role := Principal{Account: a, ARN: got.ARN}
	if d, _ := f.Authorize(ctx, Request{Principal: role, Action: "ec2:CreateVpc", Resource: "*"}); !d.Allowed {
		t.Errorf("role policy not applied: %+v", d)
	}
	if d, _ := f.Authorize(ctx, Request{Principal: role, Action: "ec2:DeleteVpc", Resource: "*"}); d.Allowed {
		t.Errorf("role allowed beyond its policy: %+v", d)
	}
	if _, err := f.AssumeRole(ctx, Principal{Account: a, ARN: eve.ARN}, r.ARN, "s2", time.Hour); resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Errorf("untrusted principal: %v", err)
	}
	for _, d := range []time.Duration{time.Minute, 2 * time.Hour} {
		if _, err := f.AssumeRole(ctx, Principal{Account: a, ARN: u.ARN}, r.ARN, "s3", d); resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Errorf("duration %v: %v", d, err)
		}
	}
	if _, err := f.AssumeRole(ctx, Principal{Account: a, ARN: u.ARN}, "arn:vws:iam::123456789012:role/none", "s4", time.Hour); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing role: %v", err)
	}
	f.Now = func() time.Time { return now.Add(16 * time.Minute) }
	if _, err := f.Authenticate(context.Background(), authReq(t, got.Key.AccessKey, got.Key.Secret, got.Key.SessionToken)); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("expired session: %v", err)
	}
}

func TestUpdateGroup(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	g, err := f.CreateGroup(ctx, a, "dev", "/old/")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateUser(ctx, a, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	p, err := f.CreatePolicy(ctx, a, "read", "/", describeOnly, "")
	if err != nil {
		t.Fatal(err)
	}
	must(t, f.AttachPolicy(ctx, a, EntityGroup, "dev", p.ARN))
	must(t, f.PutInlinePolicy(ctx, a, EntityGroup, "dev", "inline", describeOnly))
	must(t, f.AddUserToGroup(ctx, a, "dev", "bob", ""))
	if _, err := f.CreateGroup(ctx, a, "taken", "/"); err != nil {
		t.Fatal(err)
	}

	if err := f.UpdateGroup(ctx, a, "missing", "/new/", "ops", ""); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing group: %v", err)
	}
	if err := f.UpdateGroup(ctx, a, "dev", "/new/", "taken", ""); resource.CodeOf(err) != resource.CodeAlreadyExists {
		t.Errorf("duplicate name: %v", err)
	}
	if err := f.UpdateGroup(ctx, a, "dev", "new", "", ""); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("bad path: %v", err)
	}
	if err := f.UpdateGroup(ctx, a, "bad name!", "", "", ""); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("bad group name: %v", err)
	}
	if err := f.UpdateGroup(ctx, a, "dev", "", "bad name!", ""); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("bad new name: %v", err)
	}
	if got, _, err := f.GetGroup(ctx, a, "dev"); err != nil || got.Path != "/old/" {
		t.Fatalf("a rejected update changed the group to %+v: %v", got, err)
	}

	if _, err := f.CreateGroup(ctx, a, "moved", "/old/"); err != nil {
		t.Fatal(err)
	}
	must(t, f.UpdateGroup(ctx, a, "moved", "/moved/", "", ""))
	if got, _, err := f.GetGroup(ctx, a, "moved"); err != nil || got.Name != "moved" || got.Path != "/moved/" {
		t.Errorf("path-only update %+v, want moved at /moved/: %v", got, err)
	}
	if _, err := f.CreateGroup(ctx, a, "renamed", "/keep/"); err != nil {
		t.Fatal(err)
	}
	must(t, f.UpdateGroup(ctx, a, "renamed", "", "newer", ""))
	if got, _, err := f.GetGroup(ctx, a, "newer"); err != nil || got.Name != "newer" || got.Path != "/keep/" {
		t.Errorf("name-only update %+v, want newer at /keep/: %v", got, err)
	}

	must(t, f.UpdateGroup(ctx, a, "dev", "/new/", "platform", ""))
	if _, _, err := f.GetGroup(ctx, a, "dev"); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("old name still found: %v", err)
	}
	got, users, err := f.GetGroup(ctx, a, "platform")
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/new/" || got.ARN != "arn:vws:iam::123456789012:group/new/platform" || got.ID != g.ID {
		t.Errorf("renamed group %+v, want path /new/, a new ARN, and id %s", got, g.ID)
	}
	if len(users) != 1 || users[0].Name != "bob" {
		t.Errorf("members after rename %v, want bob", users)
	}
	groups, err := f.ListGroupsForUser(ctx, a, "bob")
	if err != nil || len(groups) != 1 || groups[0].Name != "platform" {
		t.Errorf("groups for bob %v, want platform: %v", groups, err)
	}
	attached, err := f.ListAttachedPolicies(ctx, a, EntityGroup, "platform")
	if err != nil || len(attached) != 1 || attached[0].ARN != p.ARN {
		t.Errorf("attached policies after rename %v, want %s: %v", attached, p.ARN, err)
	}
	inline, err := f.ListInlinePolicies(ctx, a, EntityGroup, "platform")
	if err != nil || len(inline) != 1 || inline[0] != "inline" {
		t.Errorf("inline policies after rename %v, want inline: %v", inline, err)
	}

	must(t, f.UpdateGroup(ctx, a, "platform", "", "", ""))
	if got, _, err := f.GetGroup(ctx, a, "platform"); err != nil || got.Path != "/new/" {
		t.Errorf("empty update changed the group to %+v: %v", got, err)
	}
}

func TestUpdateUser(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	u, err := f.CreateUser(ctx, a, "bob", "/old/")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateUser(ctx, a, "taken", "/"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateGroup(ctx, a, "dev", "/"); err != nil {
		t.Fatal(err)
	}
	p, err := f.CreatePolicy(ctx, a, "describe", "/", describeOnly, "")
	if err != nil {
		t.Fatal(err)
	}
	must(t, f.AddUserToGroup(ctx, a, "dev", "bob", ""))
	must(t, f.AttachPolicy(ctx, a, EntityUser, "bob", p.ARN))
	must(t, f.PutInlinePolicy(ctx, a, EntityUser, "bob", "inline", describeOnly))

	for _, tc := range []struct {
		name             string
		source, path, to string
		want             resource.Code
	}{
		{"missing user", "missing", "/new/", "ops", resource.CodeNotFound},
		{"duplicate name", "bob", "/new/", "taken", resource.CodeAlreadyExists},
		{"case-insensitive name", "bob", "", "TAKEN", resource.CodeAlreadyExists},
		{"bad path", "bob", "new", "", resource.CodeInvalidArgument},
		{"bad new name", "bob", "", "bad name!", resource.CodeInvalidArgument},
		{"reserved name", "bob", "", RootUserName, resource.CodeInvalidArgument},
		{"bad source", "bad name!", "", "", resource.CodeInvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := f.UpdateUser(ctx, a, tc.source, tc.path, tc.to, ""); resource.CodeOf(err) != tc.want {
				t.Errorf("UpdateUser(%q, %q, %q) = %v, want %v", tc.source, tc.path, tc.to, err, tc.want)
			}
		})
	}
	if got, err := f.GetUser(ctx, a, "bob"); err != nil || got.Path != "/old/" {
		t.Fatalf("a rejected update changed the user to %+v: %v", got, err)
	}
	if _, users, err := f.GetGroup(ctx, a, "dev"); err != nil || len(users) != 1 || users[0].Name != "bob" {
		t.Fatalf("a rejected update changed the members to %v: %v", users, err)
	}

	must(t, f.UpdateUser(ctx, a, "bob", "/moved/", "", ""))
	must(t, f.UpdateUser(ctx, a, "bob", "/moved/", "", "")) // the same request again is a no-op
	got, err := f.GetUser(ctx, a, "bob")
	if err != nil || got.Path != "/moved/" || got.ARN != "arn:vws:iam::123456789012:user/moved/bob" {
		t.Fatalf("path-only update %+v: %v", got, err)
	}
	must(t, f.UpdateUser(ctx, a, "bob", "", "robert", ""))
	if got, err := f.GetUser(ctx, a, "robert"); err != nil || got.Path != "/moved/" {
		t.Fatalf("name-only update %+v: %v", got, err)
	}
	if _, err := f.GetUser(ctx, a, "bob"); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("old name still found: %v", err)
	}
	must(t, f.UpdateUser(ctx, a, "robert", "/new/", "platform", ""))
	if _, err := f.GetUser(ctx, a, "robert"); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("old name still found: %v", err)
	}
	got, err = f.GetUser(ctx, a, "platform")
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/new/" || got.ARN != "arn:vws:iam::123456789012:user/new/platform" ||
		got.ID != u.ID || !got.Created.Equal(u.Created) {
		t.Errorf("renamed user %+v, want /new/, a new ARN and id %s", got, u.ID)
	}
	_, users, err := f.GetGroup(ctx, a, "dev")
	if err != nil || len(users) != 1 || users[0].Name != "platform" {
		t.Errorf("members after rename %v: %v", users, err)
	}
	groups, err := f.ListGroupsForUser(ctx, a, "platform")
	if err != nil || len(groups) != 1 || groups[0].Name != "dev" {
		t.Errorf("groups for platform %v: %v", groups, err)
	}
	attached, err := f.ListAttachedPolicies(ctx, a, EntityUser, "platform")
	if err != nil || len(attached) != 1 || attached[0].ARN != p.ARN {
		t.Errorf("attached policies after rename %v: %v", attached, err)
	}
	inline, err := f.ListInlinePolicies(ctx, a, EntityUser, "platform")
	if err != nil || len(inline) != 1 || inline[0] != "inline" {
		t.Errorf("inline policies after rename %v: %v", inline, err)
	}
	must(t, f.UpdateUser(ctx, a, "platform", "", "", ""))
	if got, err := f.GetUser(ctx, a, "platform"); err != nil || got.Path != "/new/" {
		t.Errorf("empty update changed the user to %+v: %v", got, err)
	}
}

func TestUpdateUserKeepsKeysAndSessions(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	f.Now = func() time.Time { return now }
	if _, err := f.CreateUser(ctx, a, "bob", "/old/"); err != nil {
		t.Fatal(err)
	}
	must(t, f.PutInlinePolicy(ctx, a, EntityUser, "bob", "describe", describeOnly))
	k, err := f.CreateAccessKey(ctx, a, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateLoginProfile(ctx, a, "bob", "correct horse 1"); err != nil {
		t.Fatal(err)
	}
	sess, err := f.Login(ctx, LoginRequest{Account: a, UserName: "bob", Password: "correct horse 1"})
	if err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, wantARN string) {
		t.Helper()
		c, err := verifyContext(ctx, t, f, credOf(k.AccessKeyID, k.Secret, ""))
		if err != nil || c.Principal != wantARN {
			t.Fatalf("key principal %+v: %v, want %s", c, err, wantARN)
		}
		d, err := f.Authorize(ctx, Request{
			Principal: Principal{Account: a, ARN: c.Principal}, Action: "ec2:DescribeVpcs", Resource: "*",
		})
		if err != nil || !d.Allowed {
			t.Errorf("policy after rename %+v: %v", d, err)
		}
		s, err := f.ValidateSession(ctx, sess.Token)
		if err != nil || s.Principal.ARN != wantARN {
			t.Errorf("session principal %+v: %v, want %s", s.Principal, err, wantARN)
		}
	}

	must(t, f.UpdateUser(ctx, a, "bob", "/moved/", "", ""))
	check(t, "arn:vws:iam::123456789012:user/moved/bob")
	must(t, f.UpdateUser(ctx, a, "bob", "", "robert", ""))
	check(t, "arn:vws:iam::123456789012:user/moved/robert")
	must(t, f.UpdateUser(ctx, a, "robert", "/new/", "platform", ""))
	check(t, "arn:vws:iam::123456789012:user/new/platform")
	if _, err := f.GetLoginProfile(ctx, a, "platform"); err != nil {
		t.Errorf("login profile after rename: %v", err)
	}
}

func TestUpdateUserRejectsAStaleARN(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	u, err := f.CreateUser(ctx, a, "bob", "/old/")
	if err != nil {
		t.Fatal(err)
	}
	must(t, f.UpdateUser(ctx, a, "bob", "/new/", "", u.ARN))
	if err := f.UpdateUser(ctx, a, "bob", "/other/", "", u.ARN); resource.CodeOf(err) != resource.CodeConflict {
		t.Errorf("stale update: %v", err)
	}
	if got, err := f.GetUser(ctx, a, "bob"); err != nil || got.Path != "/new/" {
		t.Errorf("a stale update changed the user to %+v: %v", got, err)
	}
}

func TestUpdateAssumeRolePolicy(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	u, _ := f.CreateUser(ctx, a, "bob", "/")
	eve, _ := f.CreateUser(ctx, a, "eve", "/")
	oldTrust := `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"` + u.ARN + `"}}]}`
	newTrust := `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"` + eve.ARN + `"}}]}`
	r, err := f.CreateRole(ctx, a, RoleInput{Name: "ops", Path: "/", TrustPolicy: oldTrust})
	if err != nil {
		t.Fatal(err)
	}
	malformed := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole"}]}`
	if err := f.UpdateAssumeRolePolicy(ctx, a, "ops", malformed); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("malformed trust policy: %v", err)
	}
	if got, _ := f.GetRole(ctx, a, "ops"); got.TrustPolicy != oldTrust {
		t.Errorf("a malformed update changed the trust policy to %s", got.TrustPolicy)
	}
	if err := f.UpdateAssumeRolePolicy(ctx, a, "none", newTrust); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing role: %v", err)
	}
	oversized := strings.Repeat("x", maxPolicyBytes+1)
	if err := f.UpdateAssumeRolePolicy(ctx, a, "ops", oversized); resource.CodeOf(err) != resource.CodeResourceExhausted {
		t.Errorf("oversized policy: %v", err)
	}
	must(t, f.UpdateAssumeRolePolicy(ctx, a, "ops", newTrust))
	if got, _ := f.GetRole(ctx, a, "ops"); got.TrustPolicy != newTrust {
		t.Fatalf("trust policy %s, want %s", got.TrustPolicy, newTrust)
	}
	if _, err := f.AssumeRole(ctx, Principal{Account: a, ARN: eve.ARN}, r.ARN, "s1", time.Hour); err != nil {
		t.Errorf("new trusted principal: %v", err)
	}
	_, err = f.AssumeRole(ctx, Principal{Account: a, ARN: u.ARN}, r.ARN, "s2", time.Hour)
	if resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Errorf("old trusted principal: %v", err)
	}
}

func TestSetDefaultPolicyVersion(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	p, err := f.CreatePolicy(ctx, a, "versioned", "/", describeOnly, "")
	if err != nil {
		t.Fatal(err)
	}
	// v1 is the default and the only version, so setting it again is a no-op.
	must(t, f.SetDefaultPolicyVersion(ctx, a, p.ARN, "v1"))
	must(t, f.SetDefaultPolicyVersion(ctx, a, p.ARN, "v1"))
	if err := f.SetDefaultPolicyVersion(ctx, a, p.ARN, "v2"); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing version: %v", err)
	}
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.SetDefaultPolicyVersion(ctx, other, p.ARN, "v1"); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("policy from another account: %v", err)
	}
	if err := f.SetDefaultPolicyVersion(ctx, a, "not-an-arn", "v1"); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("unknown policy ARN: %v", err)
	}
}

func TestDeletePolicyVersion(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	p, err := f.CreatePolicy(ctx, a, "d", "/", describeOnly, "")
	if err != nil {
		t.Fatal(err)
	}
	missing := "arn:vws:iam::123456789012:policy/none"
	if err := f.DeletePolicyVersion(ctx, a, missing, "v1"); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing policy: %v", err)
	}
	if err := f.DeletePolicyVersion(ctx, a, p.ARN, "v1"); resource.CodeOf(err) != resource.CodeConflict {
		t.Errorf("default version: %v", err)
	}
	if err := f.DeletePolicyVersion(ctx, a, p.ARN, "v2"); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing version: %v", err)
	}
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.DeletePolicyVersion(ctx, other, p.ARN, "v1"); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("policy visible from another account: %v", err)
	}
	// A new default makes v1 a non-default version, so deleting v1 succeeds.
	v, err := f.CreatePolicyVersion(ctx, a, p.ARN, describeOnly, true)
	if err != nil || v.ID != "v2" || !v.IsDefaultVersion {
		t.Fatalf("default version %+v, %v", v, err)
	}
	must(t, f.DeletePolicyVersion(ctx, a, p.ARN, "v1"))
	if err := f.DeletePolicyVersion(ctx, a, p.ARN, "v2"); resource.CodeOf(err) != resource.CodeConflict {
		t.Errorf("new default version: %v", err)
	}
	// A non-default version is removed on its own.
	p2, err := f.CreatePolicy(ctx, a, "delete-non-default", "/", describeOnly, "")
	if err != nil {
		t.Fatal(err)
	}
	v, err = f.CreatePolicyVersion(ctx, a, p2.ARN, describeOnly, false)
	if err != nil || v.ID != "v2" || v.IsDefaultVersion {
		t.Fatalf("non-default version %+v, %v", v, err)
	}
	must(t, f.DeletePolicyVersion(ctx, a, p2.ARN, "v2"))
	page, err := f.ListPolicyVersions(ctx, a, p2.ARN, "", 0)
	if err != nil || len(page.Versions) != 1 || page.Versions[0].ID != "v1" || !page.Versions[0].IsDefaultVersion {
		t.Fatalf("versions after non-default delete %+v, %v", page, err)
	}
}

func TestDeletePolicyRefusesNonDefaultVersions(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	p, err := f.CreatePolicy(ctx, a, "versioned", "/", describeOnly, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreatePolicyVersion(ctx, a, p.ARN, describeOnly, false); err != nil {
		t.Fatal(err)
	}
	if err := f.DeletePolicy(ctx, a, p.ARN); resource.CodeOf(err) != resource.CodeConflict {
		t.Errorf("policy with a non-default version: %v", err)
	}
	must(t, f.DeletePolicyVersion(ctx, a, p.ARN, "v2"))
	// The next id follows the counter, so a deleted id is not reused.
	v, err := f.CreatePolicyVersion(ctx, a, p.ARN, describeOnly, false)
	if err != nil || v.ID != "v3" {
		t.Fatalf("version after delete %+v, %v", v, err)
	}
	must(t, f.DeletePolicyVersion(ctx, a, p.ARN, "v3"))
	must(t, f.DeletePolicy(ctx, a, p.ARN))
}

func TestCreatePolicyVersion(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	p, err := f.CreatePolicy(ctx, a, "versioned", "/", describeOnly, "")
	if err != nil {
		t.Fatal(err)
	}
	readOnly := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	v, err := f.CreatePolicyVersion(ctx, a, p.ARN, readOnly, false)
	if err != nil {
		t.Fatal(err)
	}
	if v.ID != "v2" || v.IsDefaultVersion {
		t.Errorf("version %+v, want v2 not default", v)
	}
	got, err := f.GetPolicyVersion(ctx, a, p.ARN, "v2")
	if err != nil || got.Document != readOnly || got.IsDefaultVersion {
		t.Errorf("read v2 %+v, %v", got, err)
	}
	page, err := f.ListPolicyVersions(ctx, a, p.ARN, "", 0)
	if err != nil || len(page.Versions) != 2 {
		t.Fatalf("page %+v, %v", page, err)
	}
	if page.Versions[0].ID != "v1" || !page.Versions[0].IsDefaultVersion ||
		page.Versions[1].ID != "v2" || page.Versions[1].IsDefaultVersion {
		t.Errorf("versions %+v", page.Versions)
	}
	v, err = f.CreatePolicyVersion(ctx, a, p.ARN, describeOnly, true)
	if err != nil || v.ID != "v3" || !v.IsDefaultVersion {
		t.Fatalf("default version %+v, %v", v, err)
	}
	page, err = f.ListPolicyVersions(ctx, a, p.ARN, "", 0)
	if err != nil || len(page.Versions) != 3 {
		t.Fatalf("page %+v, %v", page, err)
	}
	for _, got := range page.Versions {
		if got.IsDefaultVersion != (got.ID == "v3") {
			t.Errorf("version %+v after v3 became default", got)
		}
	}
	policy, err := f.GetPolicy(ctx, a, p.ARN)
	if err != nil || policy.DefaultVersion != "v3" {
		t.Errorf("default policy %+v, %v", policy, err)
	}
	must(t, f.SetDefaultPolicyVersion(ctx, a, p.ARN, "v2"))
	policy, err = f.GetPolicy(ctx, a, p.ARN)
	if err != nil || policy.DefaultVersion != "v2" {
		t.Errorf("default policy %+v, %v", policy, err)
	}
	_, err = f.CreatePolicyVersion(ctx, a, p.ARN, "{not json", false)
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("malformed document: %v", err)
	}
	if _, err := f.GetPolicyVersion(ctx, a, p.ARN, "v9"); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing version: %v", err)
	}
	_, err = f.GetPolicyVersion(ctx, a, "not-an-arn", "v1")
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("unknown policy: %v", err)
	}
	_, err = f.CreatePolicyVersion(ctx, a, "not-an-arn", describeOnly, false)
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("unknown policy: %v", err)
	}
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.CreatePolicyVersion(ctx, other, p.ARN, describeOnly, false)
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("policy from another account: %v", err)
	}
	if _, err := f.GetPolicyVersion(ctx, other, p.ARN, "v1"); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("version visible from another account: %v", err)
	}
	for _, want := range []string{"v4", "v5"} {
		v, err = f.CreatePolicyVersion(ctx, a, p.ARN, describeOnly, false)
		if err != nil || v.ID != want {
			t.Fatalf("version %+v, want %s: %v", v, want, err)
		}
	}
	// The sixth version is the AWS quota.
	_, err = f.CreatePolicyVersion(ctx, a, p.ARN, describeOnly, false)
	if resource.CodeOf(err) != resource.CodeResourceExhausted {
		t.Errorf("sixth version: %v", err)
	}
}

func TestDefaultPolicyVersionChangesAuthorization(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	allow := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	p, err := f.CreatePolicy(ctx, a, "readable", "/", allow, "")
	if err != nil {
		t.Fatal(err)
	}
	u, err := f.CreateUser(ctx, a, "bob", "/")
	if err != nil {
		t.Fatal(err)
	}
	must(t, f.AttachPolicy(ctx, a, EntityUser, "bob", p.ARN))
	deny := `{"Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}`
	v, err := f.CreatePolicyVersion(ctx, a, p.ARN, deny, true)
	if err != nil || !v.IsDefaultVersion {
		t.Fatalf("default version %+v, %v", v, err)
	}
	req := Request{Principal: Principal{Account: a, ARN: u.ARN}, Action: "s3:GetObject", Resource: "*"}
	if d, err := f.Authorize(ctx, req); err != nil || d.Allowed {
		t.Errorf("new default version did not deny: %+v, %v", d, err)
	}
	must(t, f.SetDefaultPolicyVersion(ctx, a, p.ARN, "v1"))
	if d, err := f.Authorize(ctx, req); err != nil || !d.Allowed {
		t.Errorf("v1 default did not allow: %+v, %v", d, err)
	}
}

func TestListPolicyVersions(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	p, err := f.CreatePolicy(ctx, a, "versioned", "/", describeOnly, "")
	if err != nil {
		t.Fatal(err)
	}
	page, err := f.ListPolicyVersions(ctx, a, p.ARN, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.IsTruncated || page.Marker != "" || len(page.Versions) != 1 {
		t.Fatalf("page %+v", page)
	}
	v := page.Versions[0]
	if v.ID != "v1" || !v.IsDefaultVersion || !v.Created.Equal(p.Created) {
		t.Errorf("version %+v, want v1 default at %v", v, p.Created)
	}
	// The last page's marker resumes after the only version.
	page, err = f.ListPolicyVersions(ctx, a, p.ARN, "v1", 100)
	if err != nil || len(page.Versions) != 0 || page.IsTruncated {
		t.Errorf("resume from v1: %+v %v", page, err)
	}
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.ListPolicyVersions(ctx, other, p.ARN, "", 0); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("policy from another account: %v", err)
	}
	if _, err := f.ListPolicyVersions(ctx, a, "not-an-arn", "", 0); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("unknown policy ARN: %v", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRoleDescription(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	trust := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"*"}}]}`
	r, err := f.CreateRole(ctx, a, RoleInput{Name: "ops", Path: "/", TrustPolicy: trust, Description: "old"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.UpdateRoleDescription(ctx, a, "ops", "new")
	if err != nil || got.Description != "new" || got.ARN != r.ARN {
		t.Fatalf("update description %+v %v", got, err)
	}
	if stored, _ := f.GetRole(ctx, a, "ops"); stored.Description != "new" {
		t.Errorf("stored description %q, want new", stored.Description)
	}
	if _, err := f.UpdateRoleDescription(ctx, a, "none", "new"); resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing role: %v", err)
	}
	long := strings.Repeat("x", MaxRoleDescription+1)
	if _, err := f.UpdateRoleDescription(ctx, a, "ops", long); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("oversized description: %v", err)
	}
	if stored, _ := f.GetRole(ctx, a, "ops"); stored.Description != "new" {
		t.Errorf("a rejected update changed the description to %q", stored.Description)
	}
	for _, invalid := range []string{"\u007f", "\u0080", "\u00a0", "\u0100"} {
		if _, err := f.UpdateRoleDescription(ctx, a, "ops", invalid); resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Errorf("description %q outside the AWS pattern: %v", invalid, err)
		}
	}
	if stored, _ := f.GetRole(ctx, a, "ops"); stored.Description != "new" {
		t.Errorf("a rejected update changed the description to %q", stored.Description)
	}
	for _, valid := range []string{"\t", " ", "~", "\u00a1"} {
		if _, err := f.UpdateRoleDescription(ctx, a, "ops", valid); err != nil {
			t.Errorf("description %q inside the AWS pattern: %v", valid, err)
		}
	}
	wide := strings.Repeat("\u00ff", MaxRoleDescription)
	if got, err := f.UpdateRoleDescription(ctx, a, "ops", wide); err != nil || got.Description != wide {
		t.Errorf("1000-character description: %+v %v", got, err)
	}
	if _, err := f.CreateRole(ctx, a, RoleInput{
		Name: "svc", Path: ServiceLinkedRolePath + "compute.vws/", TrustPolicy: trust,
	}); err != nil {
		t.Fatal(err)
	}
	_, err = f.UpdateRoleDescription(ctx, a, "svc", "new")
	if resource.CodeOf(err) != resource.CodeConflict {
		t.Errorf("service-linked role: %v", err)
	}
	var e *resource.Error
	if !errors.As(err, &e) || e.Field != "UnmodifiableEntity" {
		t.Errorf("service-linked role field: %+v", err)
	}
}

func TestUpdateRole(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	trust := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"*"}}]}`
	if _, err := f.CreateRole(ctx, a, RoleInput{
		Name: "ops", Path: "/", TrustPolicy: trust, Description: "old", MaxSessionDuration: 7200,
	}); err != nil {
		t.Fatal(err)
	}
	description := "new"
	must(t, f.UpdateRole(ctx, a, "ops", RoleUpdate{Description: &description}))
	got, err := f.GetRole(ctx, a, "ops")
	if err != nil || got.Description != "new" || got.MaxSessionDuration != 7200 {
		t.Fatalf("description update %+v %v", got, err)
	}

	seconds := 43200
	must(t, f.UpdateRole(ctx, a, "ops", RoleUpdate{MaxSessionDuration: &seconds}))
	got, err = f.GetRole(ctx, a, "ops")
	if err != nil || got.Description != "new" || got.MaxSessionDuration != 43200 {
		t.Fatalf("duration update %+v %v", got, err)
	}

	empty := ""
	seconds = 3600
	must(t, f.UpdateRole(ctx, a, "ops", RoleUpdate{Description: &empty, MaxSessionDuration: &seconds}))
	got, err = f.GetRole(ctx, a, "ops")
	if err != nil || got.Description != "" || got.MaxSessionDuration != 3600 {
		t.Fatalf("both fields %+v %v", got, err)
	}
	must(t, f.UpdateRole(ctx, a, "ops", RoleUpdate{Description: &empty, MaxSessionDuration: &seconds}))

	err = f.UpdateRole(ctx, a, "none", RoleUpdate{Description: &description})
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Errorf("missing role: %v", err)
	}
	short := 3599
	err = f.UpdateRole(ctx, a, "ops", RoleUpdate{MaxSessionDuration: &short})
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("short duration: %v", err)
	}
	tooLong := 43201
	err = f.UpdateRole(ctx, a, "ops", RoleUpdate{MaxSessionDuration: &tooLong})
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("long duration: %v", err)
	}
	long := strings.Repeat("x", MaxRoleDescription+1)
	err = f.UpdateRole(ctx, a, "ops", RoleUpdate{Description: &long})
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("oversized description: %v", err)
	}
	if stored, _ := f.GetRole(ctx, a, "ops"); stored.Description != "" || stored.MaxSessionDuration != 3600 {
		t.Errorf("a rejected update changed the role: %+v", stored)
	}

	if _, err := f.CreateRole(ctx, a, RoleInput{
		Name: "svc", Path: ServiceLinkedRolePath + "compute.vws/", TrustPolicy: trust,
	}); err != nil {
		t.Fatal(err)
	}
	err = f.UpdateRole(ctx, a, "svc", RoleUpdate{Description: &description})
	var e *resource.Error
	if !errors.As(err, &e) || e.Code != resource.CodeConflict || e.Field != "UnmodifiableEntity" {
		t.Errorf("service-linked role: %+v", err)
	}
	if stored, _ := f.GetRole(ctx, a, "svc"); stored.Description != "" {
		t.Errorf("a service-linked role changed: %+v", stored)
	}
}

func TestUpdateRoleStaysInAccount(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	f := NewFake()
	trust := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"*"}}]}`
	for _, acct := range []resource.AccountID{a, other} {
		if _, err := f.CreateRole(ctx, acct, RoleInput{
			Name: "ops", Path: "/", TrustPolicy: trust, Description: acct.String(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	description := "new"
	must(t, f.UpdateRole(ctx, a, "ops", RoleUpdate{Description: &description}))
	if got, _ := f.GetRole(ctx, a, "ops"); got.Description != "new" {
		t.Errorf("caller role description %q, want new", got.Description)
	}
	if got, _ := f.GetRole(ctx, other, "ops"); got.Description != other.String() {
		t.Errorf("another account's role changed: %+v", got)
	}
}
