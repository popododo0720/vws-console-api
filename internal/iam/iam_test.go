package iam

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

var now = time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)

func account(t *testing.T) resource.AccountID {
	t.Helper()
	a, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// verify signs a request with c and runs it through a verifier backed by client.
func verify(t *testing.T, client Client, c sigv4.Credential) (resource.Caller, error) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8081/", strings.NewReader("Action=DescribeVpcs"))
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := sigv4.Sign(req, c, sigv4.ServiceEC2, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	v := sigv4.NewVerifier(sigv4.Verifier{Service: sigv4.ServiceEC2, Region: resource.RegionName, Now: func() time.Time { return now }, Auth: Authenticator(client)})
	return v.Verify(req)
}

func TestStaticKeyIsRootAndVerifiesLocally(t *testing.T) {
	s := NewStatic("AKIDEXAMPLE", "secret", account(t))
	caller, err := verify(t, s, sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret"})
	if err != nil || !caller.Root || caller.Principal != "arn:vws:iam::123456789012:root" || caller.Account != account(t) {
		t.Fatalf("static root: %+v %v", caller, err)
	}
	if _, err := verify(t, s, sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "wrong"}); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("wrong secret: %v", err)
	}
	if _, err := verify(t, s, sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", SessionToken: "tok"}); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("token with the root key: %v", err)
	}
	_, err = verify(t, s, sigv4.Credential{AccessKey: "AKIDOTHER", Secret: "secret"})
	if e := resource.AsError(err); e == nil || e.Field != "AccessKeyId" {
		t.Errorf("other key: %v, want unknown key", err)
	}
	p := Principal{Account: account(t), ARN: RootARN(account(t)), Root: true}
	if d, err := s.Authorize(t.Context(), Request{Principal: p, Action: "ec2:RunInstances", Resource: "*"}); err != nil || !d.Allowed {
		t.Fatalf("root decision %+v %v", d, err)
	}
	bob := Principal{Account: account(t), ARN: "arn:vws:iam::123456789012:user/bob"}
	if d, err := s.Authorize(t.Context(), Request{Principal: bob, Action: "ec2:RunInstances", Resource: "*"}); err != nil || d.Allowed {
		t.Fatalf("static must not allow a non-root principal: %+v %v", d, err)
	}
}

func TestFakeAuthenticatesWithItsOwnSecretsAndSessions(t *testing.T) {
	f := NewFake()
	f.Now = func() time.Time { return now }
	bob := Principal{Account: account(t), ARN: "arn:vws:iam::123456789012:user/bob"}
	role := Principal{Account: account(t), ARN: "arn:vws:sts::123456789012:assumed-role/ops/s1"}
	f.AddKey(Key{AccessKey: "AKIDBOB", Secret: "bobsecret", Principal: bob})
	f.AddKey(Key{AccessKey: "ASIATEMP", Secret: "tmp", SessionToken: "tok-1", Expires: now.Add(time.Hour), Principal: role})
	f.AddKey(Key{AccessKey: "ASIAOLD", Secret: "tmp", SessionToken: "tok-0", Expires: now, Principal: role})
	if c, err := verify(t, f, sigv4.Credential{AccessKey: "AKIDBOB", Secret: "bobsecret"}); err != nil || c.Principal != bob.ARN || c.Root {
		t.Errorf("bob: %+v %v", c, err)
	}
	if c, err := verify(t, f, sigv4.Credential{AccessKey: "ASIATEMP", Secret: "tmp", SessionToken: "tok-1"}); err != nil || c.Principal != role.ARN {
		t.Errorf("temporary: %+v %v", c, err)
	}
	for name, c := range map[string]sigv4.Credential{
		"bad secret":    {AccessKey: "AKIDBOB", Secret: "nope"},
		"missing token": {AccessKey: "ASIATEMP", Secret: "tmp"},
		"wrong token":   {AccessKey: "ASIATEMP", Secret: "tmp", SessionToken: "tok-2"},
		"expired":       {AccessKey: "ASIAOLD", Secret: "tmp", SessionToken: "tok-0"},
	} {
		if _, err := verify(t, f, c); resource.CodeOf(err) != resource.CodeUnauthenticated {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.Authenticate(t.Context(), sigv4.AuthRequest{AccessKeyID: "AKIDNOPE"}); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("unknown key: %v", err)
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

func TestWithRootKeepsStaticKeyAsAdmin(t *testing.T) {
	f := NewFake()
	bob := Key{AccessKey: "AKIDBOB", Secret: "bobsecret", Principal: Principal{Account: account(t), ARN: "arn:vws:iam::123456789012:user/bob"}}
	f.AddKey(bob)
	c := WithRoot(NewStatic("AKIDEXAMPLE", "secret", account(t)), f)
	root, err := verify(t, c, sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret"})
	if err != nil || !root.Root {
		t.Fatalf("root %+v %v", root, err)
	}
	if got, err := verify(t, c, sigv4.Credential{AccessKey: "AKIDBOB", Secret: "bobsecret"}); err != nil || got.Principal != bob.Principal.ARN {
		t.Fatalf("bob %+v %v", got, err)
	}
	if _, err := verify(t, c, sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "bobsecret"}); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Fatalf("root key with a wrong secret must not fall through: %v", err)
	}
	rootP := Principal{Account: account(t), ARN: RootARN(account(t)), Root: true}
	if d, _ := c.Authorize(t.Context(), Request{Principal: rootP, Action: "iam:CreateUser", Resource: "*"}); !d.Allowed {
		t.Fatalf("root denied: %+v", d)
	}
	if d, _ := c.Authorize(t.Context(), Request{Principal: bob.Principal, Action: "iam:CreateUser", Resource: "*"}); d.Allowed {
		t.Fatalf("bob allowed without a policy: %+v", d)
	}
}

func TestCheckMapsDenyToPermissionDenied(t *testing.T) {
	f := NewFake()
	c := resource.Caller{Account: account(t), Subject: "AKIDBOB", Principal: "arn:vws:iam::123456789012:user/bob"}
	if err := Check(t.Context(), f, c, "ec2:RunInstances", "*"); resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Fatalf("deny: %v", err)
	}
	if err := Check(t.Context(), nil, c, "ec2:RunInstances", "*"); resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Fatalf("nil authorizer must fail closed: %v", err)
	}
	root := resource.Caller{Account: account(t), Subject: "AKIDEXAMPLE", Principal: RootARN(account(t)), Root: true}
	if err := Check(t.Context(), NewStatic("AKIDEXAMPLE", "secret", account(t)), root, "ec2:RunInstances", "*"); err != nil {
		t.Fatalf("root: %v", err)
	}
}

func credOf(key, secret, token string) sigv4.Credential {
	return sigv4.Credential{AccessKey: key, Secret: secret, SessionToken: token}
}

// authReq builds the AuthRequest the verifier would send for a signed request.
func authReq(t *testing.T, key, secret, token string) sigv4.AuthRequest {
	t.Helper()
	var got sigv4.AuthRequest
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8081/", strings.NewReader("Action=DescribeVpcs"))
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := sigv4.Sign(req, credOf(key, secret, token), sigv4.ServiceEC2, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	v := sigv4.NewVerifier(sigv4.Verifier{Service: sigv4.ServiceEC2, Region: resource.RegionName, Now: func() time.Time { return now },
		Auth: captureAuth(func(r sigv4.AuthRequest) { got = r })})
	_, _ = v.Verify(req)
	return got
}

type captureAuth func(sigv4.AuthRequest)

func (c captureAuth) Authenticate(_ context.Context, r sigv4.AuthRequest) (sigv4.Identity, error) {
	c(r)
	return sigv4.Identity{}, sigv4.ErrUnknownKey
}
