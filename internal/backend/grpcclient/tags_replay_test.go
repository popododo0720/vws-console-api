package grpcclient

import (
	"context"
	"testing"
	"time"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

type stubLookup struct {
	op  *longrunningpb.Operation
	err error
	req *computev1.LookupOperationRequest
}

func (s *stubLookup) LookupOperation(
	_ context.Context, req *computev1.LookupOperationRequest, _ ...grpc.CallOption,
) (*computev1.LookupOperationResponse, error) {
	s.req = req
	if s.err != nil {
		return nil, s.err
	}
	return &computev1.LookupOperationResponse{Operation: s.op}, nil
}

// TestReplayTagsAnswersOnlyItsOwnOperation checks each LookupOperation
// outcome a refused CreateTags retry can meet (#333): only a succeeded
// update of this instance under this request id is the answer. An unknown
// or expired request id and a compute without the lookup keep the
// mismatch; an outage stays retryable; a foreign answer is internal.
func TestReplayTagsAnswersOnlyItsOwnOperation(t *testing.T) {
	const projectID = "acct-123456789012"
	id, err := resource.Parse[resource.InstanceID]("i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	requestID := requestUUID("key", "tags", "00")
	name := instanceName(projectID, id.String())
	op := func(t *testing.T, resourceName, reqID string, verb commonv1.OperationVerb) *longrunningpb.Operation {
		t.Helper()
		msg, err := longOp(projectID, "0123456789abcdef", resourceName, reqID, verb, time.Unix(1_700_000_000, 0))
		if err != nil {
			t.Fatal(err)
		}
		msg.Done = true
		return msg
	}
	update := commonv1.OperationVerb_OPERATION_VERB_UPDATE
	failed := op(t, name, requestID, update)
	failed.Result = &longrunningpb.Operation_Error{
		Error: &statuspb.Status{Code: int32(codes.Aborted), Message: "superseded"},
	}
	other := instanceName(projectID, "i-0fedcba9876543210")
	missingMeta := op(t, name, requestID, update)
	missingMeta.Metadata = nil

	for _, tc := range []struct {
		name   string
		lookup *stubLookup
		want   resource.Code
	}{
		{name: "own update", lookup: &stubLookup{op: op(t, name, requestID, update)}},
		{
			name: "unknown or expired request id", lookup: &stubLookup{err: status.Error(codes.NotFound, "no operation")},
			want: resource.CodeIdempotencyMismatch,
		},
		{
			name: "compute without the lookup", lookup: &stubLookup{err: status.Error(codes.Unimplemented, "unknown service")},
			want: resource.CodeIdempotencyMismatch,
		},
		{name: "first update failed", lookup: &stubLookup{op: failed}, want: resource.CodeIdempotencyMismatch},
		{
			name: "compute unavailable", lookup: &stubLookup{err: status.Error(codes.Unavailable, "restarting")},
			want: resource.CodeUnavailable,
		},
		{
			name: "another instance", lookup: &stubLookup{op: op(t, other, requestID, update)},
			want: resource.CodeInternal,
		},
		{
			name: "another request id", lookup: &stubLookup{op: op(t, name, requestUUID("key", "tags", "01"), update)},
			want: resource.CodeInternal,
		},
		{
			name: "not an update", lookup: &stubLookup{op: op(t, name, requestID, commonv1.OperationVerb_OPERATION_VERB_DELETE)},
			want: resource.CodeInternal,
		},
		{name: "no metadata", lookup: &stubLookup{op: missingMeta}, want: resource.CodeInternal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := computeClient{&api{lookup: tc.lookup}}
			got, err := c.replayTags(context.Background(), projectID, id, requestID, resource.IdempotencyMismatch())
			if tc.lookup.req.GetParent() != "projects/"+projectID || tc.lookup.req.GetRequestId() != requestID {
				t.Fatalf("lookup asked %v", tc.lookup.req)
			}
			if tc.want == resource.CodeUnspecified {
				if err != nil || got != tc.lookup.op {
					t.Fatalf("got %v %v, want the looked-up operation", got, err)
				}
				return
			}
			if code := resource.CodeOf(err); code != tc.want || got != nil {
				t.Fatalf("got %v %v (%s), want %s", got, err, code, tc.want)
			}
		})
	}
}
