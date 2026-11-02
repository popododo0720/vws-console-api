package s3rest

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-lib/obs"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// s3AuthError is the S3 REST error body. The signature fields are the extra
// detail AWS returns with SignatureDoesNotMatch.
type s3AuthError struct {
	Code              string `xml:"Code"`
	Message           string `xml:"Message"`
	AWSAccessKeyID    string `xml:"AWSAccessKeyId"`
	StringToSign      string `xml:"StringToSign"`
	SignatureProvided string `xml:"SignatureProvided"`
	CanonicalRequest  string `xml:"CanonicalRequest"`
	RequestID         string `xml:"RequestId"`
}

// The S3 error codes and statuses for SigV4 failures, from
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/ErrorResponses.html
// (List of error codes). The messages are S3's own text where it differs
// from that list, as vws-conformance checks it (see authError).
const (
	msgAccessDenied = "Access Denied"
	msgSignature    = "The request signature we calculated does not match the signature you provided. " +
		"Check your key and signing method."
	msgSkewed           = "The difference between the request time and the current time is too large."
	msgHeaderMalformed  = "The authorization header is malformed."
	msgUnknownKey       = "The AWS Access Key Id you provided does not exist in our records."
	msgInvalidToken     = "The provided token is malformed or otherwise not valid."
	msgExpiredToken     = "The provided token has expired."
	msgBadDigest        = "The Content-MD5 or checksum value that you specified did not match what the server received."
	sigv4ErrorRequestID = "req-245"
)

// TestSigV4FailuresUseS3ErrorCodes is #245 (vws-conformance AUTH-002 to
// AUTH-007 and the other SigV4 checks). Each failure answers with its own
// S3 code, status and documented message, and no more: never the secret,
// the signature the server expected, or which internal check refused it.
func TestSigV4FailuresUseS3ErrorCodes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	f := iam.NewFake()
	bobARN := "arn:vws:iam::123456789012:user/bob"
	f.AddKey(iam.Key{AccessKey: "AKIDBOB", Secret: "bobsecret", Principal: iam.Principal{Account: account, ARN: bobARN}})
	roleARN := "arn:vws:sts::123456789012:assumed-role/ops/s1"
	f.AddKey(iam.Key{
		AccessKey: "ASIATEMP", Secret: "tempsecret", SessionToken: "tok-live", Expires: now.Add(time.Hour),
		Principal: iam.Principal{Account: account, ARN: roleARN},
	})
	f.AddKey(iam.Key{
		AccessKey: "ASIAOLD", Secret: "oldsecret", SessionToken: "tok-old", Expires: now.Add(-time.Minute),
		Principal: iam.Principal{Account: account, ARN: roleARN},
	})
	for _, arn := range []string{bobARN, roleARN} {
		f.AddStatement(arn, iam.Statement{Effect: iam.Allow, Actions: []string{"s3:*"}, Resources: []string{"*"}})
	}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{Now: func() time.Time { return now }}).Set()})
	h := New(Config{Service: svc, Authorizer: f, Verifier: sigv4.NewVerifier(sigv4.Verifier{
		Service: sigv4.ServiceS3, Region: resource.RegionName, Now: func() time.Time { return now },
		Auth: iam.Authenticator(f),
	})})
	bob := sigv4.Credential{AccessKey: "AKIDBOB", Secret: "bobsecret", Account: account}
	temp := sigv4.Credential{AccessKey: "ASIATEMP", Secret: "tempsecret", Account: account, SessionToken: "tok-live"}
	secrets := []string{"bobsecret", "tempsecret", "oldsecret", "tok-live", "tok-old"}

	type signing struct {
		cred    sigv4.Credential
		service sigv4.Service
		region  string
		at      time.Time
	}
	ok := signing{cred: bob, service: sigv4.ServiceS3, region: resource.RegionName, at: now}
	with := func(edit func(*signing)) signing {
		s := ok
		edit(&s)
		return s
	}
	for _, tc := range []struct {
		name   string
		method string
		body   string
		sign   *signing
		after  func(*http.Request)
		status int
		code   string
		msg    string
	}{
		{name: "signed by bob", sign: &ok, status: http.StatusOK},
		{name: "temporary credential", sign: ptr(with(func(s *signing) { s.cred = temp })), status: http.StatusOK},
		{
			name: "AUTH-002 a flipped signature digit", sign: &ok, after: flipSignature,
			status: http.StatusForbidden, code: "SignatureDoesNotMatch", msg: msgSignature,
		},
		{
			name: "wrong secret", sign: ptr(with(func(s *signing) { s.cred.Secret = "not-bobs" })),
			status: http.StatusForbidden, code: "SignatureDoesNotMatch", msg: msgSignature,
		},
		{
			name: "signature is not hex", sign: &ok, after: func(r *http.Request) { setSignature(r, strings.Repeat("z", 64)) },
			status: http.StatusForbidden, code: "SignatureDoesNotMatch", msg: msgSignature,
		},
		{
			name: "AUTH-003 clock 16 minutes behind", sign: ptr(with(func(s *signing) { s.at = now.Add(-16 * time.Minute) })),
			status: http.StatusForbidden, code: "RequestTimeTooSkewed", msg: msgSkewed,
		},
		{
			name: "clock 16 minutes ahead", sign: ptr(with(func(s *signing) { s.at = now.Add(16 * time.Minute) })),
			status: http.StatusForbidden, code: "RequestTimeTooSkewed", msg: msgSkewed,
		},
		{
			name: "AUTH-004 scope names another region", sign: ptr(with(func(s *signing) { s.region = "us-east-1" })),
			status: http.StatusBadRequest, code: "AuthorizationHeaderMalformed", msg: msgHeaderMalformed,
		},
		{
			name: "AUTH-005 scope names ec2", sign: ptr(with(func(s *signing) { s.service = sigv4.ServiceEC2 })),
			status: http.StatusBadRequest, code: "AuthorizationHeaderMalformed", msg: msgHeaderMalformed,
		},
		{
			name: "scope date is not the request date", sign: &ok, after: func(r *http.Request) {
				day := now.Format("20060102")
				r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "/"+day+"/", "/20000101/", 1))
			},
			status: http.StatusBadRequest, code: "AuthorizationHeaderMalformed", msg: msgHeaderMalformed,
		},
		{
			name: "scope is not aws4_request", sign: &ok, after: func(r *http.Request) {
				r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "/aws4_request", "/aws4_other", 1))
			},
			status: http.StatusBadRequest, code: "AuthorizationHeaderMalformed", msg: msgHeaderMalformed,
		},
		{
			name: "no Signature field", sign: &ok, after: func(r *http.Request) {
				a := r.Header.Get("Authorization")
				r.Header.Set("Authorization", a[:strings.LastIndex(a, ", Signature=")])
			},
			status: http.StatusBadRequest, code: "AuthorizationHeaderMalformed", msg: msgHeaderMalformed,
		},
		{
			name: "SigV2 scheme", sign: &ok,
			after:  func(r *http.Request) { r.Header.Set("Authorization", "AWS AKIDBOB:c2lnbmF0dXJl") },
			status: http.StatusBadRequest, code: "AuthorizationHeaderMalformed", msg: msgHeaderMalformed,
		},
		{
			name: "two Authorization headers", sign: &ok,
			after:  func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) },
			status: http.StatusBadRequest, code: "AuthorizationHeaderMalformed", msg: msgHeaderMalformed,
		},
		{
			name: "AUTH-006 unknown access key", sign: ptr(with(func(s *signing) { s.cred.AccessKey = "AKIAUNKNOWN00000000" })),
			status: http.StatusForbidden, code: "InvalidAccessKeyId", msg: msgUnknownKey,
		},
		{name: "AUTH-007 unsigned", status: http.StatusForbidden, code: "AccessDenied", msg: msgAccessDenied},
		{
			name: "no X-Amz-Date", sign: &ok, after: func(r *http.Request) { r.Header.Del("X-Amz-Date") },
			status: http.StatusForbidden, code: "AccessDenied", msg: msgAccessDenied,
		},
		{
			name: "session token is not the key's", sign: ptr(with(func(s *signing) {
				s.cred.AccessKey, s.cred.Secret, s.cred.SessionToken = "ASIATEMP", "tempsecret", "tok-forged"
			})),
			status: http.StatusBadRequest, code: "InvalidToken", msg: msgInvalidToken,
		},
		{
			name: "session token with a long-term key", sign: ptr(with(func(s *signing) { s.cred.SessionToken = "tok-live" })),
			status: http.StatusBadRequest, code: "InvalidToken", msg: msgInvalidToken,
		},
		{
			name: "expired session token", sign: ptr(with(func(s *signing) {
				s.cred.AccessKey, s.cred.Secret, s.cred.SessionToken = "ASIAOLD", "oldsecret", "tok-old"
			})),
			status: http.StatusBadRequest, code: "ExpiredToken", msg: msgExpiredToken,
		},
		{
			name: "body is not the signed payload", method: http.MethodPut, body: "signed", sign: &ok,
			after:  func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 0 },
			status: http.StatusBadRequest, code: "BadDigest", msg: msgBadDigest,
		},
		{
			name: "UNSIGNED-PAYLOAD", sign: &ok,
			after:  func(r *http.Request) { r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD") },
			status: http.StatusForbidden, code: "AccessDenied", msg: msgAccessDenied,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method, target := http.MethodGet, "http://127.0.0.1:8082/"
			if tc.method != "" {
				method, target = tc.method, "http://127.0.0.1:8082/sigv4-errors/a.txt"
			}
			req := httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(tc.body))
			req.Host = req.URL.Host
			req.Header.Set("X-Request-Id", "req-wire")
			req = req.WithContext(obs.WithRequestID(req.Context(), sigv4ErrorRequestID))
			if tc.sign != nil {
				if err := sigv4.Sign(req, tc.sign.cred, tc.sign.service, tc.sign.region, tc.sign.at); err != nil {
					t.Fatal(err)
				}
			}
			sent := signatureOf(req)
			if tc.after != nil {
				tc.after(req)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.status, rec.Body)
			}
			if tc.code == "" {
				return
			}
			body := rec.Body.String()
			var got s3AuthError
			if err := xml.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("body %q: %v", body, err)
			}
			if got.Code != tc.code || got.Message != tc.msg || got.RequestID != sigv4ErrorRequestID {
				t.Errorf("got %s %q (request id %q), want %s %q", got.Code, got.Message, got.RequestID, tc.code, tc.msg)
			}
			for _, s := range secrets {
				// A signed session token is in the canonical request S3
				// echoes to its own sender; no other secret may appear.
				echoed := tc.sign != nil && s == tc.sign.cred.SessionToken
				if strings.Contains(body, s) && !echoed {
					t.Errorf("body carries %q: %s", s, body)
				}
			}
			if tc.code != "SignatureDoesNotMatch" {
				if got.StringToSign != "" || got.CanonicalRequest != "" || got.SignatureProvided != "" || got.AWSAccessKeyID != "" {
					t.Errorf("%s carries signature detail: %s", tc.code, body)
				}
				return
			}
			// AWS returns what it computed from the request, so the
			// caller can compare it with its own: never the signature it
			// expected.
			if got.AWSAccessKeyID != tc.sign.cred.AccessKey || got.SignatureProvided != signatureOf(req) {
				t.Errorf("key %q signature %q, want %q %q",
					got.AWSAccessKeyID, got.SignatureProvided, tc.sign.cred.AccessKey, signatureOf(req))
			}
			scope := now.Format("20060102") + "/" + resource.RegionName + "/s3/aws4_request"
			if !strings.HasPrefix(got.StringToSign, "AWS4-HMAC-SHA256\n"+now.Format("20060102T150405Z")+"\n"+scope+"\n") ||
				!strings.HasPrefix(got.CanonicalRequest, "GET\n/\n") {
				t.Errorf("string to sign %q, canonical request %q", got.StringToSign, got.CanonicalRequest)
			}
			if want := expectedSignature(t, req, bob, now); strings.Contains(body, want) && want != sent {
				t.Errorf("body carries the expected signature %s", want)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

func signatureOf(r *http.Request) string {
	a := r.Header.Get("Authorization")
	if i := strings.LastIndex(a, "Signature="); i >= 0 {
		return a[i+len("Signature="):]
	}
	return ""
}

func setSignature(r *http.Request, sig string) {
	a := r.Header.Get("Authorization")
	r.Header.Set("Authorization", a[:strings.LastIndex(a, "Signature=")+len("Signature=")]+sig)
}

// flipSignature changes the first digit, as vws-conformance AUTH-002 does.
func flipSignature(r *http.Request) {
	sig := signatureOf(r)
	digit := "0"
	if sig[0] == '0' {
		digit = "1"
	}
	setSignature(r, digit+sig[1:])
}

// expectedSignature is the signature bob's secret gives for r's headers.
func expectedSignature(t *testing.T, r *http.Request, cred sigv4.Credential, at time.Time) string {
	t.Helper()
	again := httptest.NewRequestWithContext(t.Context(), r.Method, r.URL.String(), nil)
	again.Host = r.Host
	if err := sigv4.Sign(again, cred, sigv4.ServiceS3, resource.RegionName, at); err != nil {
		t.Fatal(err)
	}
	return signatureOf(again)
}
