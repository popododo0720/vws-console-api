package ec2query

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

type wireErr struct {
	Status int
	Code   string
}

func ec2Wire(t *testing.T, e *resource.Error) wireErr {
	t.Helper()
	rec := httptest.NewRecorder()
	writeErr(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil), e)
	var body errorXML
	if err := xml.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%v: %v", e.Code, err)
	}
	return wireErr{rec.Code, body.Code}
}

// TestEveryCodeHasAnEC2Error pins the EC2 code and status for each model
// code. A new code fails here until it has a row.
//
// Client errors are a 400-series response. That set includes InvalidAction
// and every *.NotFound code, answered here as 400. Server errors are a
// 500-series response. RequestLimitExceeded is in that set and is 503.
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
func TestEveryCodeHasAnEC2Error(t *testing.T) {
	want := map[resource.Code]wireErr{
		resource.CodeInvalidArgument:     {400, "InvalidParameterValue"},
		resource.CodeNotFound:            {400, "InvalidParameterValue"},
		resource.CodeAlreadyExists:       {400, "InvalidParameterValue"},
		resource.CodeConflict:            {400, "IncorrectInstanceState"},
		resource.CodeIdempotencyMismatch: {400, "IdempotentParameterMismatch"},
		resource.CodeUnauthenticated:     {401, "AuthFailure"},
		resource.CodePermissionDenied:    {403, "UnauthorizedOperation"},
		resource.CodeResourceExhausted:   {503, "RequestLimitExceeded"},
		resource.CodePayloadTooLarge:     {400, "InvalidParameterValue"},
		resource.CodeUnavailable:         {503, "Unavailable"},
		resource.CodeUnimplemented:       {400, "InvalidAction"},
		resource.CodeInternal:            {500, "InternalError"},
	}
	if len(want) != len(resource.Codes()) {
		t.Errorf("%d rows for %d codes", len(want), len(resource.Codes()))
	}
	for _, c := range resource.Codes() {
		w, ok := want[c]
		if !ok {
			t.Errorf("%v has no EC2 row", c)
			continue
		}
		if got := ec2Wire(t, &resource.Error{Code: c, Message: "m"}); got != w {
			t.Errorf("%v = %+v, want %+v", c, got, w)
		}
	}
}

func TestEC2ErrorByKind(t *testing.T) {
	for _, tc := range []struct {
		code resource.Code
		kind resource.Kind
		want wireErr
	}{
		{resource.CodeNotFound, resource.KindInstance, wireErr{400, "InvalidInstanceID.NotFound"}},
		{resource.CodeNotFound, resource.KindSubnet, wireErr{400, "InvalidSubnetID.NotFound"}},
		{resource.CodeNotFound, resource.KindImage, wireErr{400, "InvalidAMIID.NotFound"}},
		{resource.CodeNotFound, resource.KindVpc, wireErr{400, "InvalidVpcID.NotFound"}},
		{resource.CodeNotFound, resource.KindVolume, wireErr{400, "InvalidVolume.NotFound"}},
		{resource.CodeNotFound, resource.KindSecurityGroup, wireErr{400, "InvalidGroup.NotFound"}},
		{resource.CodeNotFound, resource.KindKeyPair, wireErr{400, "InvalidKeyPair.NotFound"}},
		{resource.CodeNotFound, resource.KindAddress, wireErr{400, "InvalidAllocationID.NotFound"}},
		{resource.CodeNotFound, resource.KindSnapshot, wireErr{400, "InvalidSnapshot.NotFound"}},
		{resource.CodeAlreadyExists, resource.KindSecurityGroup, wireErr{400, "InvalidGroup.Duplicate"}},
		{resource.CodeAlreadyExists, resource.KindKeyPair, wireErr{400, "InvalidKeyPair.Duplicate"}},
		{resource.CodeConflict, resource.KindInstance, wireErr{400, "IncorrectInstanceState"}},
		{resource.CodeConflict, resource.KindUnspecified, wireErr{400, "IncorrectInstanceState"}},
		{resource.CodeConflict, resource.KindVolume, wireErr{400, "IncorrectState"}},
		{resource.CodeConflict, resource.KindVpc, wireErr{400, "DependencyViolation"}},
		{resource.CodeConflict, resource.KindSubnet, wireErr{400, "DependencyViolation"}},
	} {
		if got := ec2Wire(t, &resource.Error{Code: tc.code, Kind: tc.kind, Message: "m"}); got != tc.want {
			t.Errorf("%v %v = %+v, want %+v", tc.code, tc.kind, got, tc.want)
		}
	}
}
