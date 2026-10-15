package s3rest

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

// TestEveryCodeHasAnS3Error pins the S3 code and status for each model
// code. A new code fails here until it has a row.
//
// NoSuchBucket and NoSuchKey are 404. EntityTooLarge is 400.
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/ErrorResponses.html
func TestEveryCodeHasAnS3Error(t *testing.T) {
	want := map[resource.Code]wireErr{
		resource.CodeInvalidArgument:     {400, "InvalidArgument"},
		resource.CodeNotFound:            {404, "NoSuchBucket"},
		resource.CodeAlreadyExists:       {409, "BucketAlreadyExists"},
		resource.CodeConflict:            {409, "BucketNotEmpty"},
		resource.CodeIdempotencyMismatch: {409, "OperationAborted"},
		resource.CodeUnauthenticated:     {403, "AccessDenied"},
		resource.CodePermissionDenied:    {403, "AccessDenied"},
		resource.CodeResourceExhausted:   {503, "SlowDown"},
		resource.CodePayloadTooLarge:     {400, "EntityTooLarge"},
		resource.CodeUnavailable:         {503, "ServiceUnavailable"},
		resource.CodeUnimplemented:       {501, "NotImplemented"},
		resource.CodeInternal:            {500, "InternalError"},
	}
	if len(want) != len(resource.Codes()) {
		t.Errorf("%d rows for %d codes", len(want), len(resource.Codes()))
	}
	for _, c := range resource.Codes() {
		w, ok := want[c]
		if !ok {
			t.Errorf("%v has no S3 row", c)
			continue
		}
		if got := s3Wire(t, &resource.Error{Code: c, Message: "m"}); got != w {
			t.Errorf("%v = %+v, want %+v", c, got, w)
		}
	}
	if got := s3Wire(t, &resource.Error{Code: resource.CodeNotFound, Kind: resource.KindObject}); got != (wireErr{404, "NoSuchKey"}) {
		t.Errorf("object not found = %+v", got)
	}
}

func s3Wire(t *testing.T, e *resource.Error) wireErr {
	t.Helper()
	rec := httptest.NewRecorder()
	writeErr(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/b/k", nil), e, "/b/k")
	var body errorXML
	if err := xml.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%v: %v", e.Code, err)
	}
	return wireErr{rec.Code, body.Code}
}
