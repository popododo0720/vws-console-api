package grpcclient

import (
	"context"
	"testing"
	"time"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestBucketCreateContract runs the #315 CreateBucket table over the gRPC
// client against the loopback, whose bucket service replays request ids and
// answers a create for a held bucket with a succeeded operation, as
// vws-storage does.
func TestBucketCreateContract(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	world := fake.New(fake.Options{Now: func() time.Time { return now }, Entropy: &fake.Sequence{}})
	backendtest.BucketCreate(t, dialLoopback(t, world, now))
}

// inflightBuckets is a bucket service where the bucket is not readable yet
// and CreateBucket returns another request's running create: vws-storage's
// answer while a create for the same bucket is in flight.
type inflightBuckets struct {
	storagev1.BucketServiceClient
	sent []string
}

func (b *inflightBuckets) GetBucket(context.Context, *storagev1.GetBucketRequest, ...grpc.CallOption) (*storagev1.Bucket, error) {
	return nil, status.Error(codes.NotFound, "bucket not found")
}

func (b *inflightBuckets) CreateBucket(_ context.Context, in *storagev1.CreateBucketRequest, _ ...grpc.CallOption) (*longrunningpb.Operation, error) {
	b.sent = append(b.sent, in.GetRequestId())
	projectID, err := projectOfName(in.GetParent())
	if err != nil {
		return nil, err
	}
	return runningNamed(projectID, "0f8fad5b-d9cb-469f-a165-70867728950e",
		bucketName(projectID, in.GetBucketId()), commonv1.OperationVerb_OPERATION_VERB_CREATE, time.Unix(1_700_000_000, 0))
}

// TestCreateBucketInFlightForAnotherRequestIsOwned covers the create that
// races one already running in the same project: the operation answers
// another request id, so this request did not create the bucket and the
// caller already owns it (#315).
func TestCreateBucketInFlightForAnotherRequestIsOwned(t *testing.T) {
	stub := &inflightBuckets{}
	client := storageClient{&api{buckets: stub}}
	name, err := resource.Parse[resource.BucketName]("racing")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateBucket(t.Context(), backend.Scope{Account: mustAccount(t)}, name)
	if !resource.OwnedByCaller(err) {
		t.Fatalf("err = %v, want BucketAlreadyOwned", err)
	}
	if len(stub.sent) != 1 || stub.sent[0] == "0f8fad5b-d9cb-469f-a165-70867728950e" {
		t.Fatalf("request ids sent %v", stub.sent)
	}
}

// TestBucketRequestIDsAreFreshPerCall covers #315's request-id bug. vws-storage
// returns the stored operation for any request id it has seen, so a create
// or delete that sends a fixed id per bucket name answers a second create or
// delete with the first one's operation and changes nothing: within 24 hours
// create, delete, create left no bucket, and a second delete left the bucket.
func TestBucketRequestIDsAreFreshPerCall(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	world := fake.New(fake.Options{Now: func() time.Time { return now }, Entropy: &fake.Sequence{}})
	set := dialLoopback(t, world, now)()
	ctx := t.Context()
	scope := backend.Scope{Account: mustAccount(t)}
	name, err := resource.Parse[resource.BucketName]("again-and-again")
	if err != nil {
		t.Fatal(err)
	}
	for round := 1; round <= 2; round++ {
		if _, err := set.Storage.CreateBucket(ctx, scope, name); err != nil {
			t.Fatalf("round %d create: %v", round, err)
		}
		if _, err := set.Storage.GetBucket(ctx, scope, name); err != nil {
			t.Fatalf("round %d: bucket missing after create: %v", round, err)
		}
		if err := set.Storage.DeleteBucket(ctx, scope, name); err != nil {
			t.Fatalf("round %d delete: %v", round, err)
		}
		if _, err := set.Storage.GetBucket(ctx, scope, name); resource.CodeOf(err) != resource.CodeNotFound {
			t.Fatalf("round %d: bucket still there after delete: %v", round, err)
		}
	}
}

// TestDeleteBucketAfterRecreateDeletesAgain isolates DeleteBucket from the
// create path: the bucket is made again in the store directly, and a second
// delete through the client must remove it, not replay the first delete.
func TestDeleteBucketAfterRecreateDeletesAgain(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	world := fake.New(fake.Options{Now: func() time.Time { return now }, Entropy: &fake.Sequence{}})
	set := dialLoopback(t, world, now)()
	ctx := t.Context()
	scope := backend.Scope{Account: mustAccount(t)}
	name, err := resource.Parse[resource.BucketName]("deleted-twice")
	if err != nil {
		t.Fatal(err)
	}
	for round := 1; round <= 2; round++ {
		if _, err := world.Set().Storage.CreateBucket(ctx, scope, name); err != nil {
			t.Fatalf("round %d store create: %v", round, err)
		}
		if err := set.Storage.DeleteBucket(ctx, scope, name); err != nil {
			t.Fatalf("round %d delete: %v", round, err)
		}
		if _, err := world.Set().Storage.GetBucket(ctx, scope, name); resource.CodeOf(err) != resource.CodeNotFound {
			t.Fatalf("round %d: bucket still there after delete: %v", round, err)
		}
	}
}
