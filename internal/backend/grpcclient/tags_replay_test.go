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

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
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
// outcome a refused CreateTags retry can meet besides its own succeeded
// update, which backendtest.TagsReplay covers (#333). An unknown or expired
// request id, a compute without the lookup, a failed first update and an
// update of another instance (the token at this position tagged it) keep
// the mismatch; an outage stays retryable; an answer for another request id
// or verb is internal.
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
			want: resource.CodeIdempotencyMismatch,
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
			got, _, err := c.replayTags(context.Background(), projectID, id, map[string]string{"team": "storage"},
				requestID, resource.IdempotencyMismatch())
			if tc.lookup.req.GetParent() != "projects/"+projectID || tc.lookup.req.GetRequestId() != requestID {
				t.Fatalf("lookup asked %v", tc.lookup.req)
			}
			if code := resource.CodeOf(err); code != tc.want || got != nil {
				t.Fatalf("got %v %v (%s), want %s", got, err, code, tc.want)
			}
		})
	}
}

// readHook runs hook before the second GetInstance, the read CreateTags
// builds its label write from.
type readHook struct {
	computev1.InstanceServiceClient
	reads int
	hook  func()
}

func (h *readHook) GetInstance(
	ctx context.Context, req *computev1.GetInstanceRequest, opts ...grpc.CallOption,
) (*computev1.Instance, error) {
	h.reads++
	if h.reads == 2 {
		h.hook()
	}
	return h.InstanceServiceClient.GetInstance(ctx, req, opts...)
}

// TestTagsReplayReadsTheTagsAfterTheRefusal is a same-token CreateTags
// retry that races another CreateTags changing one of its tags and adding
// one, so compute refuses the rebuilt body. The retry's first read still
// shows its tags, but the instance no longer carries them when compute
// refuses the retry, so it is a mismatch and the other value stays (#333
// review).
func TestTagsReplayReadsTheTagsAfterTheRefusal(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()
	world := fake.New(fake.Options{Now: func() time.Time { return now }, Entropy: &fake.Sequence{}})
	set := dialLoopback(t, world, now)()
	account := mustAccount(t)
	scope := backend.Scope{Account: account}
	mut := func(key string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: key, Fingerprint: "fp-" + key}
	}
	sub, err := set.Network.CreateSubnet(ctx, mut("sub"), resource.CreateSubnetRequest{Cidr: "10.2.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	img, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	run, err := set.Compute.RunInstances(ctx, mut("run"), resource.RunInstancesRequest{
		ImageID: img, InstanceType: "vws.small", SubnetID: sub.Items[0].ID, Count: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Compute.GetOperation(ctx, scope, run.Operation.ID); err != nil {
		t.Fatal(err)
	}
	id := run.Items[0].ID
	req := resource.CreateTagsRequest{IDs: []resource.InstanceID{id}, Tags: map[string]string{"env": "old"}}
	if _, err := set.Compute.CreateTags(ctx, mut("tags"), req); err != nil {
		t.Fatal(err)
	}
	base, ok := set.Compute.(computeClient)
	if !ok {
		t.Fatalf("compute is %T", set.Compute)
	}
	shared := *base.api
	shared.instances = &readHook{InstanceServiceClient: base.instances, hook: func() {
		if _, err := base.CreateTags(ctx, mut("concurrent"), resource.CreateTagsRequest{
			IDs: req.IDs, Tags: map[string]string{"env": "new", "team": "storage"},
		}); err != nil {
			t.Errorf("concurrent CreateTags: %v", err)
		}
	}}
	_, err = computeClient{&shared}.CreateTags(ctx, mut("tags"), req)
	if resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
		t.Fatalf("retry after its tag changed: %v, want IdempotencyMismatch", err)
	}
	current, err := base.getInstance(ctx, project(account), id.String())
	if err != nil || current.Tags["env"] != "new" {
		t.Fatalf("env after the retry %q (%v), want new", current.Tags["env"], err)
	}
}
