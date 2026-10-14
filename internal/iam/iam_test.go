package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func account(t *testing.T) resource.AccountID {
	t.Helper()
	a, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestStaticKeyIsRootAndAllowed(t *testing.T) {
	s := NewStatic("AKIDEXAMPLE", "secret", account(t))
	cred, err := s.GetSigningCredential(t.Context(), "AKIDEXAMPLE")
	if err != nil || cred.Secret != "secret" || !cred.Principal.Root || cred.Principal.ARN != "arn:vws:iam::123456789012:root" {
		t.Fatalf("static credential %+v %v", cred, err)
	}
	if _, err := s.GetSigningCredential(t.Context(), "AKIDOTHER"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("other key: %v, want ErrUnknownKey", err)
	}
	d, err := s.Authorize(t.Context(), Request{Principal: cred.Principal, Action: "ec2:RunInstances", Resource: "*"})
	if err != nil || !d.Allowed {
		t.Fatalf("root decision %+v %v", d, err)
	}
	d, err = s.Authorize(t.Context(), Request{Principal: Principal{Account: account(t), ARN: "arn:vws:iam::123456789012:user/bob"}, Action: "ec2:RunInstances", Resource: "*"})
	if err != nil || d.Allowed {
		t.Fatalf("static must not allow a non-root principal: %+v %v", d, err)
	}
}

func TestFakePolicyEvaluation(t *testing.T) {
	f := NewFake()
	bob := Principal{Account: account(t), ARN: "arn:vws:iam::123456789012:user/bob"}
	f.AddStatement(bob.ARN, Statement{Effect: Allow, Actions: []string{"ec2:Describe*", "s3:*"}, Resources: []string{"*"}})
	f.AddStatement(bob.ARN, Statement{Effect: Deny, Actions: []string{"s3:DeleteObject"}, Resources: []string{"arn:vws:s3:::locked/*"}})
	for _, tc := range []struct {
		action, resource string
		want             bool
	}{
		{"ec2:DescribeVpcs", "*", true},
		{"ec2:RunInstances", "*", false},
		{"s3:DeleteObject", "arn:vws:s3:::open/a.txt", true},
		{"s3:DeleteObject", "arn:vws:s3:::locked/a.txt", false},
		{"EC2:describevpcs", "*", true},
	} {
		d, err := f.Authorize(t.Context(), Request{Principal: bob, Action: tc.action, Resource: tc.resource})
		if err != nil || d.Allowed != tc.want {
			t.Errorf("%s on %s: %+v %v, want allowed=%v", tc.action, tc.resource, d, err, tc.want)
		}
	}
}

type countingClient struct {
	Client
	calls int
}

func (c *countingClient) GetSigningCredential(ctx context.Context, key string) (SigningCredential, error) {
	c.calls++
	return c.Client.GetSigningCredential(ctx, key)
}

func TestCacheHonoursTTL(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	inner := &countingClient{Client: NewStatic("AKIDEXAMPLE", "secret", account(t))}
	c := NewCache(inner, time.Minute, func() time.Time { return now })
	for range 3 {
		if _, err := c.GetSigningCredential(t.Context(), "AKIDEXAMPLE"); err != nil {
			t.Fatal(err)
		}
	}
	if inner.calls != 1 {
		t.Fatalf("calls within ttl = %d, want 1", inner.calls)
	}
	now = now.Add(2 * time.Minute)
	if _, err := c.GetSigningCredential(t.Context(), "AKIDEXAMPLE"); err != nil || inner.calls != 2 {
		t.Fatalf("after ttl: calls %d err %v, want 2", inner.calls, err)
	}
	if _, err := c.GetSigningCredential(t.Context(), "AKIDNOPE"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key through cache: %v", err)
	}
}

func TestWithRootKeepsStaticKeyAsAdmin(t *testing.T) {
	f := NewFake()
	bob := SigningCredential{AccessKey: "AKIDBOB", Secret: "bobsecret", Principal: Principal{Account: account(t), ARN: "arn:vws:iam::123456789012:user/bob"}}
	f.AddKey(bob)
	c := WithRoot(NewStatic("AKIDEXAMPLE", "secret", account(t)), f)
	root, err := c.GetSigningCredential(t.Context(), "AKIDEXAMPLE")
	if err != nil || !root.Principal.Root {
		t.Fatalf("root %+v %v", root, err)
	}
	if got, err := c.GetSigningCredential(t.Context(), "AKIDBOB"); err != nil || got.Secret != "bobsecret" {
		t.Fatalf("bob %+v %v", got, err)
	}
	if d, _ := c.Authorize(t.Context(), Request{Principal: root.Principal, Action: "iam:CreateUser", Resource: "*"}); !d.Allowed {
		t.Fatalf("root denied: %+v", d)
	}
	if d, _ := c.Authorize(t.Context(), Request{Principal: bob.Principal, Action: "iam:CreateUser", Resource: "*"}); d.Allowed {
		t.Fatalf("bob allowed without a policy: %+v", d)
	}
}

func TestCheckMapsDenyToPermissionDenied(t *testing.T) {
	f := NewFake()
	c := resource.Caller{Account: account(t), Subject: "AKIDBOB", Principal: "arn:vws:iam::123456789012:user/bob"}
	err := Check(t.Context(), f, c, "ec2:RunInstances", "*")
	if resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Fatalf("deny: %v", err)
	}
	if err := Check(t.Context(), nil, c, "ec2:RunInstances", "*"); resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Fatalf("nil authorizer must fail closed: %v", err)
	}
	root := resource.Caller{Account: account(t), Subject: "AKIDEXAMPLE", Principal: "arn:vws:iam::123456789012:root", Root: true}
	if err := Check(t.Context(), NewStatic("AKIDEXAMPLE", "secret", account(t)), root, "ec2:RunInstances", "*"); err != nil {
		t.Fatalf("root: %v", err)
	}
}
