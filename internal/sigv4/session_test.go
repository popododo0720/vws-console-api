package sigv4

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

type authFunc func(ctx context.Context, req AuthRequest) (Identity, error)

func (f authFunc) Authenticate(ctx context.Context, req AuthRequest) (Identity, error) {
	return f(ctx, req)
}

// The verifier hands the authenticator the scope, canonical request,
// string-to-sign, signature and session token, and never a secret.
func TestVerifierDelegatesToAuthenticator(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	temp := Credential{AccessKey: "ASIATEMP", Secret: "tmpsecret", Account: account, SessionToken: "tok-1"}
	var got AuthRequest
	v := NewVerifier(Verifier{Service: ServiceEC2, Region: resource.RegionName, Now: func() time.Time { return now },
		Auth: authFunc(func(_ context.Context, req AuthRequest) (Identity, error) {
			got = req
			switch req.AccessKeyID {
			case "AKIDDOWN":
				return Identity{}, errors.New("iam unreachable")
			case "AKIDBADSIG":
				return Identity{}, resource.Unauthenticated("signature mismatch")
			case temp.AccessKey:
				if !req.VerifiedBy(temp.Secret) {
					return Identity{}, resource.Unauthenticated("signature mismatch")
				}
				return Identity{Account: account, Principal: "arn:vws:sts::123456789012:assumed-role/ops/s1"}, nil
			}
			return Identity{}, ErrUnknownKey
		})})

	caller, err := v.Verify(signed(t, temp, ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", "Action=DescribeVpcs"))
	if err != nil || caller.Principal != "arn:vws:sts::123456789012:assumed-role/ops/s1" || caller.Subject != "ASIATEMP" {
		t.Fatalf("temporary credential: %+v %v", caller, err)
	}
	if got.Date != "20261009" || got.Region != resource.RegionName || got.Service != ServiceEC2 || got.SessionToken != "tok-1" ||
		len(got.Signature) != 64 || !strings.HasPrefix(got.StringToSign, "AWS4-HMAC-SHA256\n20261009T100000Z\n20261009/vws-1/ec2/aws4_request\n") ||
		!strings.HasPrefix(got.CanonicalRequest, "POST\n/\n") {
		t.Errorf("auth request %+v", got)
	}
	for _, tc := range []struct {
		key   string
		code  resource.Code
		field string
	}{
		{"AKIDNOPE", resource.CodeUnauthenticated, "AccessKeyId"},
		{"AKIDBADSIG", resource.CodeUnauthenticated, ""},
		{"AKIDDOWN", resource.CodeUnavailable, ""},
	} {
		c := Credential{AccessKey: tc.key, Secret: "x", Account: account}
		_, err := v.Verify(signed(t, c, ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", "Action=DescribeVpcs"))
		if e := resource.AsError(err); e == nil || e.Code != tc.code || e.Field != tc.field {
			t.Errorf("%s: %v, want %v field %q", tc.key, err, tc.code, tc.field)
		}
	}
}

func TestCheckSession(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, want, got string
		expires         time.Time
		ok              bool
	}{
		{"long-term key", "", "", time.Time{}, true},
		{"token with long-term key", "", "tok", time.Time{}, false},
		{"matching", "tok", "tok", now.Add(time.Minute), true},
		{"missing", "tok", "", now.Add(time.Minute), false},
		{"wrong", "tok", "nope", now.Add(time.Minute), false},
		{"expired", "tok", "tok", now, false},
	} {
		if err := CheckSession(tc.want, tc.got, tc.expires, now); (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}
