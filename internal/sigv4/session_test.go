package sigv4

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

type keyFunc func(ctx context.Context, key string) (Credential, error)

func (f keyFunc) SigningCredential(ctx context.Context, key string) (Credential, error) {
	return f(ctx, key)
}

func TestSessionTokenAndKeyStoreErrors(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	temp := Credential{AccessKey: "ASIATEMP", Secret: "tmpsecret", Account: account, SessionToken: "tok-1",
		Principal: "arn:vws:sts::123456789012:assumed-role/ops/s1", Expires: now.Add(time.Hour)}
	expired := temp
	expired.AccessKey, expired.Expires = "ASIAOLD", now.Add(-time.Minute)
	v := NewVerifier(Verifier{Service: ServiceEC2, Region: resource.RegionName, Now: func() time.Time { return now },
		Keys: keyFunc(func(_ context.Context, key string) (Credential, error) {
			switch key {
			case temp.AccessKey:
				return temp, nil
			case expired.AccessKey:
				return expired, nil
			case "AKIDDOWN":
				return Credential{}, errors.New("iam unreachable")
			}
			return Credential{}, ErrUnknownKey
		})})

	caller, err := v.Verify(signed(t, temp, ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", "Action=DescribeVpcs"))
	if err != nil || caller.Principal != temp.Principal {
		t.Fatalf("temporary credential: %+v %v", caller, err)
	}
	noToken := temp
	noToken.SessionToken = ""
	if _, err := v.Verify(signed(t, noToken, ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", "Action=DescribeVpcs")); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("missing session token: %v", err)
	}
	wrong := temp
	wrong.SessionToken = "tok-2"
	if _, err := v.Verify(signed(t, wrong, ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", "Action=DescribeVpcs")); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("wrong session token: %v", err)
	}
	if _, err := v.Verify(signed(t, expired, ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", "Action=DescribeVpcs")); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("expired credential: %v", err)
	}
	unknown := Credential{AccessKey: "AKIDNOPE", Secret: "x", Account: account}
	_, err = v.Verify(signed(t, unknown, ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", "Action=DescribeVpcs"))
	if e := resource.AsError(err); e == nil || e.Code != resource.CodeUnauthenticated || e.Field != "AccessKeyId" {
		t.Errorf("unknown key: %v, want Unauthenticated on AccessKeyId", err)
	}
	down := Credential{AccessKey: "AKIDDOWN", Secret: "x", Account: account}
	if _, err := v.Verify(signed(t, down, ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", "Action=DescribeVpcs")); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Errorf("key store down: %v, want Unavailable", err)
	}
}
