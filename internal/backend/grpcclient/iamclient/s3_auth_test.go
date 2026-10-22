package iamclient

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/s3rest"
)

// TestS3AnswersVwsIAMRefusalsWithS3Codes is #245 over gRPC. vws-iam checks
// the signature and answers a refusal with its AWS code in ErrorInfo
// aws_code; S3 must answer each with its own S3 error, as it does for the
// fake (s3rest TestSigV4FailuresUseS3ErrorCodes), and never echo vws-iam's
// message.
func TestS3AnswersVwsIAMRefusalsWithS3Codes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	const iamText = "vws-iam internal wording"
	for _, tc := range []struct {
		name   string
		answer error
		status int
		code   string
		msg    string
	}{
		{"accepted", nil, http.StatusOK, "", ""},
		{
			"InvalidClientTokenId", awsErrMsg(codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId", iamText),
			http.StatusForbidden, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.",
		},
		{
			"SignatureDoesNotMatch", awsErrMsg(codes.Unauthenticated, "INVALID_CREDENTIALS", "SignatureDoesNotMatch", iamText),
			http.StatusForbidden, "SignatureDoesNotMatch",
			"The request signature we calculated does not match the signature you provided. " +
				"Check your key and signing method.",
		},
		{
			"ExpiredToken", awsErrMsg(codes.Unauthenticated, "TOKEN_EXPIRED", "ExpiredToken", iamText),
			http.StatusBadRequest, "ExpiredToken", "The provided token has expired.",
		},
		{
			"RequestTimeTooSkewed", awsErrMsg(codes.Unauthenticated, "INVALID_CREDENTIALS", "RequestTimeTooSkewed", iamText),
			http.StatusForbidden, "RequestTimeTooSkewed",
			"The difference between the request time and the current time is too large.",
		},
		{
			"IncompleteSignature", awsErrMsg(codes.Unauthenticated, "INVALID_CREDENTIALS", "IncompleteSignature", iamText),
			http.StatusBadRequest, "AuthorizationHeaderMalformed", "The authorization header is malformed.",
		},
		{
			"MissingAuthenticationToken",
			awsErrMsg(codes.Unauthenticated, "INVALID_CREDENTIALS", "MissingAuthenticationToken", iamText),
			http.StatusForbidden, "AccessDenied", "Access Denied",
		},
		{
			"vws-iam fails", status.Error(codes.Internal, iamText),
			http.StatusServiceUnavailable, "ServiceUnavailable", "authentication unavailable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := harness(t)
			s.authnErr = tc.answer
			svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{Now: func() time.Time { return now }}).Set()})
			h := s3rest.New(s3rest.Config{Service: svc, Authorizer: c, Verifier: sigv4.NewVerifier(sigv4.Verifier{
				Service: sigv4.ServiceS3, Region: resource.RegionName, Now: func() time.Time { return now },
				Auth: iam.Authenticator(c),
			})})
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:8082/", nil)
			req.Host = req.URL.Host
			cred := sigv4.Credential{AccessKey: "AKIABOB", Secret: "bobsecret", Account: account}
			if err := sigv4.Sign(req, cred, sigv4.ServiceS3, resource.RegionName, now); err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.status, rec.Body)
			}
			if tc.code == "" {
				return
			}
			var got struct {
				Code         string `xml:"Code"`
				Message      string `xml:"Message"`
				StringToSign string `xml:"StringToSign"`
			}
			if err := xml.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.Code != tc.code || got.Message != tc.msg {
				t.Errorf("got %s %q, want %s %q", got.Code, got.Message, tc.code, tc.msg)
			}
			if strings.Contains(rec.Body.String(), iamText) || strings.Contains(rec.Body.String(), "bobsecret") {
				t.Errorf("body leaks: %s", rec.Body)
			}
			if (tc.code == "SignatureDoesNotMatch") != (got.StringToSign != "") {
				t.Errorf("string to sign %q on %s", got.StringToSign, tc.code)
			}
		})
	}
}

// awsErrMsg is awsErr with vws-iam's own message, which must not reach S3.
func awsErrMsg(code codes.Code, reason, aws, msg string) error {
	info := &errdetails.ErrorInfo{Reason: reason, Domain: "vws.dev", Metadata: map[string]string{"aws_code": aws}}
	st, err := status.New(code, msg).WithDetails(info)
	if err != nil {
		panic(err)
	}
	return st.Err()
}
