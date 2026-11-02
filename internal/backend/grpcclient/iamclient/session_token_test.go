package iamclient

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// GetSessionToken names the caller only in the authentication oneof, sends
// duration, serial and code as given, and returns the credentials.
func TestGetSessionTokenSendsTheCallersAuthentication(t *testing.T) {
	c, s := harness(t)
	bob, err := c.Authenticate(t.Context(), signed)
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.GetSessionToken(t.Context(), bob, 2*time.Hour, "arn:vws:iam::123456789012:mfa/bob", "123456")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.sessionTok) != 1 {
		t.Fatalf("%d GetSessionToken calls", len(s.sessionTok))
	}
	req := s.sessionTok[0]
	if req.GetDurationSeconds() != 7200 || req.GetSerialNumber() != "arn:vws:iam::123456789012:mfa/bob" ||
		req.GetTokenCode() != "123456" {
		t.Errorf("request %v", req)
	}
	if req.GetCaller() != nil { //nolint:staticcheck // asserting the deprecated field stays unset.
		t.Error("the deprecated caller field was sent")
	}
	if !proto.Equal(req.GetSigv4(), s.authn[0]) {
		t.Errorf("sigv4 %v, want the caller's AuthenticateRequest %v", req.GetSigv4(), s.authn[0])
	}
	if k.AccessKey != "ASIASESSIONBOB000000" || k.Secret != "session-secret-must-not-leak" ||
		k.SessionToken != "session-token-must-not-leak" || !k.Expires.Equal(authTime.Add(12*time.Hour)) ||
		k.Principal.ARN != bob.ARN || k.Principal.Account != bob.Account {
		t.Errorf("key %+v", k)
	}
	for _, md := range s.md {
		for key := range md {
			if strings.HasPrefix(key, "x-vws-") {
				t.Errorf("caller metadata %q sent: the caller goes in the request", key)
			}
		}
	}
	if s.noDeadline != 0 {
		t.Errorf("%d calls had no deadline", s.noDeadline)
	}
}

func TestGetSessionTokenWithoutAVWSIAMCredentialMakesNoCall(t *testing.T) {
	c, s := harness(t)
	root := iam.Principal{Account: account(t), ARN: "arn:vws:iam::123456789012:root", Root: true}
	if _, err := c.GetSessionToken(t.Context(), root, 0, "", ""); resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Errorf("static root: %v", err)
	}
	user := iam.Principal{Account: account(t), ARN: "arn:vws:iam::123456789012:user/bob"}
	if _, err := c.GetSessionToken(t.Context(), user, 0, "", ""); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("no proof: %v", err)
	}
	if len(s.sessionTok) != 0 {
		t.Errorf("%d GetSessionToken calls", len(s.sessionTok))
	}
}

// Each vws-iam failure keeps the AWS code the surface answers, and nothing
// is retried: GetSessionToken issues credentials.
func TestGetSessionTokenErrorsAndNoRetry(t *testing.T) {
	const denied, region = resource.CodePermissionDenied, iam.RegionDisabled
	for _, tc := range []struct {
		name  string
		err   error
		code  resource.Code
		field string
	}{
		{"session credentials", awsErr(codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied"), denied, ""},
		{"region disabled", awsErr(codes.PermissionDenied, "REGION_DISABLED", region), denied, region},
		{"region disabled on another code", awsErr(codes.FailedPrecondition, "REGION_DISABLED", region), denied, region},
		{"bad duration", awsErr(codes.InvalidArgument, "INVALID", "ValidationError"), resource.CodeInvalidArgument, ""},
		{"expired key", awsErr(codes.Unauthenticated, "EXPIRED", "ExpiredToken"), resource.CodeUnauthenticated, ""},
		{"unavailable", status.Error(codes.Unavailable, "down"), resource.CodeInternal, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := harness(t)
			bob, err := c.Authenticate(t.Context(), signed)
			if err != nil {
				t.Fatal(err)
			}
			s.sessionErr = tc.err
			_, err = c.GetSessionToken(t.Context(), bob, 0, "", "")
			e := resource.AsError(err)
			if e.Code != tc.code || e.Field != tc.field {
				t.Errorf("%v: code %v field %q, want %v %q", err, e.Code, e.Field, tc.code, tc.field)
			}
			if len(s.sessionTok) != 1 {
				t.Errorf("%d GetSessionToken calls: STS issues credentials and is not retried", len(s.sessionTok))
			}
		})
	}
}

func TestGetSessionTokenRefusesIncompleteCredentials(t *testing.T) {
	c, s := harness(t)
	bob, err := c.Authenticate(t.Context(), signed)
	if err != nil {
		t.Fatal(err)
	}
	s.sessionRes = &iamv1.GetSessionTokenResponse{Credentials: &iamv1.Credentials{
		AccessKeyId: "ASIAX", SecretAccessKey: "half-issued-secret", ExpireTime: timestamppb.New(authTime),
	}}
	_, err = c.GetSessionToken(t.Context(), bob, 0, "", "")
	if resource.CodeOf(err) != resource.CodeInternal || strings.Contains(err.Error(), "half-issued-secret") {
		t.Errorf("incomplete credentials: %v, want internal without the secret", err)
	}
}

// The issued secret and session token and the MFA token code appear in no
// log record or error of the client.
func TestGetSessionTokenSecretsAreNeverLogged(t *testing.T) {
	const code = "918273"
	var buf bytes.Buffer
	c, s := harness(t)
	c.SetLogger(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	bob, err := c.Authenticate(t.Context(), signed)
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.GetSessionToken(t.Context(), bob, 0, "arn:vws:iam::123456789012:mfa/bob", code)
	if err != nil {
		t.Fatal(err)
	}
	s.sessionErr = awsErr(codes.PermissionDenied, "MFA", "AccessDenied")
	_, denied := c.GetSessionToken(t.Context(), bob, 0, "arn:vws:iam::123456789012:mfa/bob", code)
	var seen strings.Builder
	seen.WriteString(buf.String())
	fmt.Fprint(&seen, denied)
	for _, secret := range []string{k.Secret, k.SessionToken, code} {
		if strings.Contains(seen.String(), secret) {
			t.Errorf("%q appears in a log record, error or printed request: %s", secret, seen.String())
		}
	}
	// The code still reaches vws-iam in its field.
	if got := s.sessionTok[0].GetTokenCode(); got != code {
		t.Errorf("token code %q not sent", got)
	}
}
