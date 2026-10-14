package iam

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
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
	must(t, f.AddUserToGroup(ctx, a, "readers", "bob"))
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
	if err := f.DeleteUser(ctx, a, "bob"); resource.CodeOf(err) != resource.CodeConflict {
		t.Errorf("delete user in a group with a policy: %v", err)
	}
	must(t, f.RemoveUserFromGroup(ctx, a, "readers", "bob"))
	must(t, f.DeleteInlinePolicy(ctx, a, EntityUser, "bob", "deny-vols"))
	must(t, f.DeleteUser(ctx, a, "bob"))
	must(t, f.DetachPolicy(ctx, a, EntityGroup, "readers", p.ARN))
	must(t, f.DeletePolicy(ctx, a, p.ARN))
	must(t, f.DeleteGroup(ctx, a, "readers"))
}

func TestAccessKeysAuthenticate(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	f.Now = func() time.Time { return now }
	if _, err := f.CreateUser(ctx, a, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(ctx, a, "bob")
	if err != nil || !strings.HasPrefix(k.AccessKeyID, "AKIA") || len(k.AccessKeyID) != 20 || len(k.Secret) != 40 || k.Status != "Active" {
		t.Fatalf("create key %+v %v", k, err)
	}
	if c, err := verify(t, f, credOf(k.AccessKeyID, k.Secret, "")); err != nil || c.Principal != "arn:vws:iam::123456789012:user/bob" {
		t.Fatalf("new key: %+v %v", c, err)
	}
	keys, err := f.ListAccessKeys(ctx, a, "bob")
	if err != nil || len(keys) != 1 || keys[0].AccessKeyID != k.AccessKeyID {
		t.Fatalf("list keys %+v %v", keys, err)
	}
	must(t, f.DeleteAccessKey(ctx, a, "bob", k.AccessKeyID))
	if _, err := verify(t, f, credOf(k.AccessKeyID, k.Secret, "")); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Fatalf("deleted key still works: %v", err)
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

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
