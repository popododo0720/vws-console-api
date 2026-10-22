package iamquery

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

type wireErr struct {
	Status int
	Code   string
}

func iamWire(t *testing.T, service sigv4.Service, e *resource.Error) wireErr {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	(&exchange{w: rec, r: req, service: service}).fail(e)
	var body errorXML
	if err := xml.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%v: %v", e.Code, err)
	}
	return wireErr{rec.Code, body.Code}
}

// TestEveryCodeHasAnIAMError pins the IAM status and code for each model
// code. A new code fails here until it has a row.
//
// https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteUser.html
// https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicy.html
// https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateLoginProfile.html
// https://docs.aws.amazon.com/IAM/latest/APIReference/CommonErrors.html
// SignatureDoesNotMatch is documented with the S3 errors.
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/ErrorResponses.html
func TestEveryCodeHasAnIAMError(t *testing.T) {
	want := map[resource.Code]wireErr{
		resource.CodeInvalidArgument:     {400, "InvalidInput"},
		resource.CodeNotFound:            {404, "NoSuchEntity"},
		resource.CodeAlreadyExists:       {409, "EntityAlreadyExists"},
		resource.CodeConflict:            {409, "DeleteConflict"},
		resource.CodeIdempotencyMismatch: {400, "InvalidInput"},
		resource.CodeUnauthenticated:     {403, "SignatureDoesNotMatch"},
		resource.CodePermissionDenied:    {403, "AccessDenied"},
		resource.CodeResourceExhausted:   {409, "LimitExceeded"},
		resource.CodePayloadTooLarge:     {400, "InvalidInput"},
		resource.CodeUnavailable:         {503, "ServiceUnavailable"},
		resource.CodeUnimplemented:       {400, "InvalidAction"},
		resource.CodeInternal:            {500, "ServiceFailure"},
	}
	if len(want) != len(resource.Codes()) {
		t.Errorf("%d rows for %d codes", len(want), len(resource.Codes()))
	}
	for _, c := range resource.Codes() {
		w, ok := want[c]
		if !ok {
			t.Errorf("%v has no IAM row", c)
			continue
		}
		if got := iamWire(t, sigv4.ServiceIAM, &resource.Error{Code: c, Message: "m"}); got != w {
			t.Errorf("%v = %+v, want %+v", c, got, w)
		}
	}
}

func TestIAMErrorByField(t *testing.T) {
	for _, tc := range []struct {
		name    string
		service sigv4.Service
		err     *resource.Error
		want    wireErr
	}{
		{
			name: "access key", service: sigv4.ServiceIAM,
			err:  &resource.Error{Code: resource.CodeUnauthenticated, Field: "AccessKeyId", Message: "unknown"},
			want: wireErr{403, "InvalidClientTokenId"},
		},
		{
			name: "expired token", service: sigv4.ServiceSTS,
			err:  &resource.Error{Code: resource.CodeUnauthenticated, Message: "token expired"},
			want: wireErr{403, "ExpiredToken"},
		},
		{
			name: "missing signature", service: sigv4.ServiceIAM,
			err:  &resource.Error{Code: resource.CodeUnauthenticated, Message: "missing signature"},
			want: wireErr{403, "MissingAuthenticationToken"},
		},
		{
			name: "unmodifiable role", service: sigv4.ServiceIAM,
			err:  &resource.Error{Code: resource.CodeConflict, Field: "UnmodifiableEntity", Message: "service-linked"},
			want: wireErr{400, "UnmodifiableEntity"},
		},
		{
			name: "policy document", service: sigv4.ServiceIAM,
			err:  &resource.Error{Code: resource.CodeInvalidArgument, Field: "PolicyDocument", Message: "bad"},
			want: wireErr{400, "MalformedPolicyDocument"},
		},
		{
			name: "password", service: sigv4.ServiceIAM,
			err:  &resource.Error{Code: resource.CodeInvalidArgument, Field: "Password", Message: "short"},
			want: wireErr{400, "PasswordPolicyViolation"},
		},
		{
			name: "sts input", service: sigv4.ServiceSTS,
			err:  &resource.Error{Code: resource.CodeInvalidArgument, Message: "bad"},
			want: wireErr{400, "ValidationError"},
		},
		{
			name: "member", service: sigv4.ServiceIAM,
			err:  &resource.Error{Code: resource.CodeInvalidArgument, Field: "userName", Message: "bad"},
			want: wireErr{400, "ValidationError"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := iamWire(t, tc.service, tc.err); got != tc.want {
				t.Errorf("%+v, want %+v", got, tc.want)
			}
		})
	}
}
