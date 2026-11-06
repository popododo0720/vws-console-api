package iam

import (
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestGetSessionToken(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	f.Now = func() time.Time { return now }
	u, _ := f.CreateUser(ctx, a, "bob", "/eng/")
	bob := Principal{Account: a, ARN: u.ARN}
	root := Principal{Account: a, ARN: "arn:vws:iam::123456789012:root", Root: true}

	for _, tc := range []struct {
		name   string
		caller Principal
		asked  time.Duration
		want   time.Duration
	}{
		{"user default", bob, 0, 12 * time.Hour},
		{"user minimum", bob, 15 * time.Minute, 15 * time.Minute},
		{"user maximum", bob, 36 * time.Hour, 36 * time.Hour},
		{"root default", root, 0, time.Hour},
		{"root above an hour is cut to an hour", root, 36 * time.Hour, time.Hour},
	} {
		k, err := f.GetSessionToken(ctx, tc.caller, SessionTokenRequest{Duration: tc.asked})
		if err != nil || !k.Expires.Equal(now.Add(tc.want)) || k.Principal.ARN != tc.caller.ARN ||
			k.Principal.Ref.MFA {
			t.Errorf("%s: %+v %v", tc.name, k, err)
			continue
		}
		c, err := verify(t, f, credOf(k.AccessKey, k.Secret, k.SessionToken))
		if err != nil || c.Principal != tc.caller.ARN || c.Root != tc.caller.Root {
			t.Errorf("%s: temporary key authenticates as %+v %v", tc.name, c, err)
		}
	}
	refused := func(name string, p Principal, req SessionTokenRequest, want resource.Code) {
		t.Helper()
		if _, err := f.GetSessionToken(ctx, p, req); resource.CodeOf(err) != want {
			t.Errorf("%s: %v", name, err)
		}
	}
	refused("a minute", bob, SessionTokenRequest{Duration: time.Minute}, resource.CodeInvalidArgument)
	refused("past 36 hours", bob, SessionTokenRequest{Duration: 36*time.Hour + time.Second}, resource.CodeInvalidArgument)
	assumed := Principal{Account: a, ARN: "arn:vws:sts::123456789012:assumed-role/ops/s1"}
	refused("assumed role", assumed, SessionTokenRequest{}, resource.CodePermissionDenied)
	refused("serial without a code", bob, SessionTokenRequest{SerialNumber: "arn:vws:iam::123456789012:mfa/x"},
		resource.CodePermissionDenied)
}

func TestGetSessionTokenWithMFA(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	f.Now = func() time.Time { return now }
	seed := []byte("12345678901234567890")
	u, _ := f.CreateUser(ctx, a, "bob", "/")
	eve, _ := f.CreateUser(ctx, a, "eve", "/")
	serial := f.AddTOTPMfaDevice(a, "bob-phone", seed)
	must(t, f.AssignMfaDevice(a, serial, "bob", time.Time{}))
	unassigned := f.AddTOTPMfaDevice(a, "spare", seed)
	bob := Principal{Account: a, ARN: u.ARN}
	code := TOTPCode(seed, now)

	denied := func(name string, p Principal, serial, code string) {
		t.Helper()
		_, err := f.GetSessionToken(ctx, p, SessionTokenRequest{SerialNumber: serial, TokenCode: code})
		if resource.CodeOf(err) != resource.CodePermissionDenied {
			t.Errorf("%s: %v", name, err)
		}
	}
	denied("wrong code", bob, serial, "000000")
	denied("another user's device", Principal{Account: a, ARN: eve.ARN}, serial, code)
	denied("unassigned device", bob, unassigned, code)
	denied("unknown device", bob, "arn:vws:iam::123456789012:mfa/none", code)

	k, err := f.GetSessionToken(ctx, bob, SessionTokenRequest{SerialNumber: serial, TokenCode: code})
	if err != nil || !k.Principal.Ref.MFA || !k.Principal.Ref.AuthTime.Equal(now) {
		t.Fatalf("mfa session %+v %v", k, err)
	}
	c, err := verify(t, f, credOf(k.AccessKey, k.Secret, k.SessionToken))
	if err != nil || !c.Ref.MFA {
		t.Errorf("mfa session authenticates as %+v %v", c, err)
	}
	denied("replayed code", bob, serial, code)

	next := now.Add(30 * time.Second)
	f.Now = func() time.Time { return next }
	nextReq := SessionTokenRequest{SerialNumber: serial, TokenCode: TOTPCode(seed, next)}
	if _, err := f.GetSessionToken(ctx, bob, nextReq); err != nil {
		t.Errorf("next code: %v", err)
	}
	f.Now = func() time.Time { return now.Add(2 * time.Minute) }
	denied("stale code", bob, serial, TOTPCode(seed, now.Add(time.Minute)))
}
