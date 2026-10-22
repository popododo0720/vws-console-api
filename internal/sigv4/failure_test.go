package sigv4

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestVerifyNamesEachFailure is #245. Each SigV4 check that refuses a
// request names its Failure, so S3 can answer with its own AWS code. The
// code, field and message stay what EC2 and IAM already map, so their
// answers do not change.
func TestVerifyNamesEachFailure(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	c := cred(t)
	temp := Credential{
		AccessKey: "ASIATEMP", Secret: "tmpsecret", Account: c.Account, SessionToken: "tok-1", Expires: now.Add(time.Hour),
	}
	old := Credential{
		AccessKey: "ASIAOLD", Secret: "oldsecret", Account: c.Account, SessionToken: "tok-2", Expires: now.Add(-time.Hour),
	}
	keys := map[string]Credential{c.AccessKey: c, temp.AccessKey: temp, old.AccessKey: old}
	v := NewVerifier(Verifier{
		Service: ServiceS3, Region: resource.RegionName, Now: func() time.Time { return now },
		Auth: authFunc(func(_ context.Context, req AuthRequest) (Identity, error) {
			k, ok := keys[req.AccessKeyID]
			switch {
			case req.AccessKeyID == "AKIDPLAIN":
				// An authenticator that does not name the failure: a
				// signature mismatch is the only check left to it.
				return Identity{}, resource.Unauthenticated("bad signature")
			case !ok:
				return Identity{}, ErrUnknownKey
			}
			if err := CheckSession(k.SessionToken, req.SessionToken, k.Expires, now); err != nil {
				return Identity{}, err
			}
			if !req.VerifiedBy(k.Secret) {
				return Identity{}, SignatureMismatch()
			}
			return Identity{Account: k.Account}, nil
		}),
	})
	get := func(cr Credential, service Service, region string, at time.Time) *http.Request {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:8082/", nil)
		r.Host = r.URL.Host
		if err := Sign(r, cr, service, region, at); err != nil {
			t.Fatal(err)
		}
		return r
	}
	ok := func() *http.Request { return get(c, ServiceS3, resource.RegionName, now) }
	edit := func(f func(*http.Request)) func() *http.Request {
		return func() *http.Request {
			r := ok()
			f(r)
			return r
		}
	}
	setAuth := func(f func(string) string) func() *http.Request {
		return edit(func(r *http.Request) { r.Header.Set("Authorization", f(r.Header.Get("Authorization"))) })
	}
	for _, tc := range []struct {
		name    string
		req     func() *http.Request
		failure Failure
		code    resource.Code
		field   string
		message string
	}{
		{
			name:    "no Authorization",
			req:     edit(func(r *http.Request) { r.Header.Del("Authorization") }),
			failure: FailureUnsigned, code: resource.CodeUnauthenticated, field: "",
			message: "missing signature",
		},
		{
			name:    "another scheme",
			req:     setAuth(func(string) string { return "AWS AKIDEXAMPLE:c2ln" }),
			failure: FailureMalformed, code: resource.CodeUnauthenticated, field: "",
			message: "missing signature",
		},
		{
			name: "two Authorization headers",
			req: edit(func(r *http.Request) {
				r.Header.Add("Authorization", r.Header.Get("Authorization"))
			}),
			failure: FailureMalformed, code: resource.CodeInvalidArgument, field: "Authorization",
			message: "repeated",
		},
		{
			name:    "a field without =",
			req:     setAuth(func(a string) string { return a + ", Junk" }),
			failure: FailureMalformed, code: resource.CodeInvalidArgument, field: "Authorization",
			message: "malformed",
		},
		{
			name:    "an unknown field",
			req:     setAuth(func(a string) string { return a + ", Extra=1" }),
			failure: FailureMalformed, code: resource.CodeInvalidArgument, field: "Authorization",
			message: "unknown field",
		},
		{
			name: "a repeated field",
			req: setAuth(func(a string) string {
				return strings.Replace(a, ", SignedHeaders=", ", Credential=x, SignedHeaders=", 1)
			}),
			failure: FailureMalformed, code: resource.CodeInvalidArgument, field: "Authorization",
			message: "repeated field",
		},
		{
			name:    "a short signature",
			req:     setAuth(func(a string) string { return a[:len(a)-2] }),
			failure: FailureMalformed, code: resource.CodeInvalidArgument, field: "Authorization",
			message: "incomplete",
		},
		{
			name:    "host not signed",
			req:     setAuth(func(a string) string { return strings.Replace(a, "SignedHeaders=host;", "SignedHeaders=", 1) }),
			failure: FailureMalformed, code: resource.CodeInvalidArgument, field: "Authorization",
			message: "host is not signed",
		},
		{
			name:    "no X-Amz-Date",
			req:     edit(func(r *http.Request) { r.Header.Del("X-Amz-Date") }),
			failure: FailureDenied, code: resource.CodeInvalidArgument, field: "X-Amz-Date",
			message: "malformed",
		},
		{
			name:    "clock behind",
			req:     func() *http.Request { return get(c, ServiceS3, resource.RegionName, now.Add(-16*time.Minute)) },
			failure: FailureSkewed, code: resource.CodeUnauthenticated, field: "",
			message: "request time is outside the allowed window",
		},
		{
			name:    "another region",
			req:     func() *http.Request { return get(c, ServiceS3, "us-east-1", now) },
			failure: FailureMalformed, code: resource.CodeUnauthenticated, field: "",
			message: "credential scope rejected",
		},
		{
			name:    "another service",
			req:     func() *http.Request { return get(c, ServiceEC2, resource.RegionName, now) },
			failure: FailureMalformed, code: resource.CodeUnauthenticated, field: "",
			message: "credential scope rejected",
		},
		{
			name: "unknown key",
			req: func() *http.Request {
				return get(Credential{AccessKey: "AKIDNOPE", Secret: "x"}, ServiceS3, resource.RegionName, now)
			},
			failure: FailureUnknownKey, code: resource.CodeUnauthenticated, field: "AccessKeyId",
			message: "The access key ID you provided does not exist in our records.",
		},
		{
			name: "wrong secret",
			req: func() *http.Request {
				return get(Credential{AccessKey: c.AccessKey, Secret: "wrong"}, ServiceS3, resource.RegionName, now)
			},
			failure: FailureSignature, code: resource.CodeUnauthenticated, field: "",
			message: "signature mismatch",
		},
		{
			name:    "signature is not hex",
			req:     setAuth(func(a string) string { return a[:len(a)-64] + strings.Repeat("z", 64) }),
			failure: FailureSignature, code: resource.CodeUnauthenticated, field: "",
			message: "signature mismatch",
		},
		{
			name: "an authenticator that names no failure",
			req: func() *http.Request {
				return get(Credential{AccessKey: "AKIDPLAIN", Secret: "x"}, ServiceS3, resource.RegionName, now)
			},
			failure: FailureSignature, code: resource.CodeUnauthenticated, field: "",
			message: "bad signature",
		},
		{
			name: "forged session token",
			req: func() *http.Request {
				f := temp
				f.SessionToken = "tok-forged"
				return get(f, ServiceS3, resource.RegionName, now)
			},
			failure: FailureInvalidToken, code: resource.CodeUnauthenticated, field: "",
			message: "the security token included in the request is invalid",
		},
		{
			name: "session token with a long-term key",
			req: func() *http.Request {
				f := c
				f.SessionToken = "tok-1"
				return get(f, ServiceS3, resource.RegionName, now)
			},
			failure: FailureInvalidToken, code: resource.CodeUnauthenticated, field: "",
			message: "security token sent with a long-term key",
		},
		{
			name:    "expired session token",
			req:     func() *http.Request { return get(old, ServiceS3, resource.RegionName, now) },
			failure: FailureExpiredToken, code: resource.CodeUnauthenticated, field: "",
			message: "the security token included in the request is expired",
		},
		{
			name:    "UNSIGNED-PAYLOAD",
			req:     edit(func(r *http.Request) { r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD") }),
			failure: FailureDenied, code: resource.CodeUnauthenticated, field: "",
			message: "unsigned payload is not accepted",
		},
		{
			name:    "content-type not signed",
			req:     edit(func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }),
			failure: FailureDenied, code: resource.CodeUnauthenticated, field: "",
			message: "content-type is not signed",
		},
		{
			name: "a payload hash the request did not sign",
			req: edit(func(r *http.Request) {
				r.Body = http.NoBody
				r.Header.Set("X-Amz-Content-Sha256", strings.Repeat("0", 64))
			}),
			failure: FailureSignature, code: resource.CodeUnauthenticated, field: "",
			message: "signature mismatch",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(tc.req())
			e := resource.AsError(err)
			rej, tagged := RejectionOf(err)
			if e == nil || !tagged || rej.Failure != tc.failure ||
				e.Code != tc.code || e.Field != tc.field || e.Message != tc.message {
				t.Fatalf("got %v (failure %v), want %q %v %q %q", err, rej, tc.failure, tc.code, tc.field, tc.message)
			}
			detail := rej.StringToSign + rej.CanonicalRequest + rej.SignatureProvided + rej.AccessKeyID
			if tc.failure != FailureSignature && detail != "" {
				t.Errorf("%q carries signature detail: %+v", tc.failure, rej)
			}
		})
	}
}

// A payload hash that the signature covers but the body does not match is
// FailurePayloadHash: the signature is good, the body is not what was signed.
func TestVerifyPayloadHashFailure(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	c := cred(t)
	r := signed(t, c, ServiceS3, now, http.MethodPut, "http://127.0.0.1:8082/b/k", "signed body")
	r.Body = http.NoBody
	_, err := verifier(c, ServiceS3, now).Verify(r)
	rej, ok := RejectionOf(err)
	if !ok || rej.Failure != FailurePayloadHash || resource.AsError(err).Message != "payload hash mismatch" {
		t.Fatalf("got %v", err)
	}
}

// A signature mismatch carries what the verifier computed from the request,
// as S3 returns it, and the signature as sent. The error text that reaches
// logs names only the failure: no request data, no secret.
func TestSignatureMismatchDetail(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	c := cred(t)
	var seen AuthRequest
	v := NewVerifier(Verifier{
		Service: ServiceS3, Region: resource.RegionName, Now: func() time.Time { return now },
		Auth: authFunc(func(_ context.Context, req AuthRequest) (Identity, error) {
			seen = req
			return Identity{}, SignatureMismatch()
		}),
	})
	r := signed(t, c, ServiceS3, now, http.MethodGet, "http://127.0.0.1:8082/", "")
	sent := strings.ToUpper(signatureOf(r))
	r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), signatureOf(r), sent, 1))
	_, err := v.Verify(r)
	rej, ok := RejectionOf(err)
	if !ok || rej.Failure != FailureSignature {
		t.Fatalf("got %v", err)
	}
	if rej.AccessKeyID != c.AccessKey || rej.StringToSign != seen.StringToSign ||
		rej.CanonicalRequest != seen.CanonicalRequest || rej.SignatureProvided != sent {
		t.Errorf("detail %+v, authenticator saw %+v", rej, seen)
	}
	for _, leak := range []string{c.Secret, seen.StringToSign, seen.CanonicalRequest, sent, c.AccessKey} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error text %q carries %q", err.Error(), leak)
		}
	}
}
