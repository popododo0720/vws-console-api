package grpcclient

import (
	"context"
	"net"
	"sync"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// deletingBuckets is a bucket service that answers as vws-storage does
// around a delete (internal/storage/bucket.go, admitCreateBucket): a create
// for a bucket the project holds in Deleting, or for a name another project
// holds, is ALREADY_EXISTS. GetBucket answers the project's own bucket with
// RECONCILIATION_STATE_DELETING while the delete runs. hiddenReads is how
// many GetBucket calls answer NOT_FOUND first, as when the bucket row is
// read before the delete is admitted, or the read races a replica.
type deletingBuckets struct {
	storagev1.UnimplementedBucketServiceServer
	mu          sync.Mutex
	own         bool
	hiddenReads int
	reads       int
	creates     int
}

func (b *deletingBuckets) GetBucket(
	_ context.Context, in *storagev1.GetBucketRequest,
) (*storagev1.Bucket, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reads++
	if !b.own || b.reads <= b.hiddenReads {
		return nil, status.Error(codes.NotFound, "bucket not found")
	}
	return &storagev1.Bucket{
		Name: in.GetName(),
		Spec: &storagev1.BucketSpec{Region: resource.RegionName},
		Status: &storagev1.BucketStatus{
			Observed: &commonv1.ObservedState{State: commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING},
		},
	}, nil
}

func (b *deletingBuckets) CreateBucket(
	context.Context, *storagev1.CreateBucketRequest,
) (*longrunningpb.Operation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.creates++
	if b.own {
		return nil, status.Error(codes.AlreadyExists, "already exists: bucket")
	}
	return nil, status.Error(codes.AlreadyExists, "already exists: bucket name is held by another account")
}

func deletingClient(t *testing.T, srv *deletingBuckets) storageClient {
	t.Helper()
	lis := bufconn.Listen(MaxMessageBytes())
	gs := grpc.NewServer()
	storagev1.RegisterBucketServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///storage",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return storageClient{&api{buckets: storagev1.NewBucketServiceClient(conn)}}
}

// TestCreateBucketWhileOwnBucketDeletes covers #321 over gRPC. A create for
// a name the caller's own bucket holds while vws-storage deletes it must be
// BucketDeleting (S3 409 OperationAborted), never BucketAlreadyOwned (a
// usable bucket) or a plain ALREADY_EXISTS (S3 BucketAlreadyExists, which
// says another account holds the name). A name another account holds stays
// ALREADY_EXISTS and is not owned.
func TestCreateBucketWhileOwnBucketDeletes(t *testing.T) {
	cases := []struct {
		name         string
		srv          *deletingBuckets
		wantDeleting bool
		wantCreates  int
	}{
		{"deleting bucket visible to the first read", &deletingBuckets{own: true}, true, 0},
		{"deleting bucket hidden from the first read", &deletingBuckets{own: true, hiddenReads: 1}, true, 1},
		{"name held by another account", &deletingBuckets{}, false, 1},
	}
	name, err := resource.Parse[resource.BucketName]("going-away")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := deletingClient(t, tc.srv)
			_, err := client.CreateBucket(t.Context(), backend.Scope{Account: mustAccount(t)}, name)
			if err == nil {
				t.Fatal("create succeeded")
			}
			if got := resource.IsBucketDeleting(err); got != tc.wantDeleting {
				t.Errorf("IsBucketDeleting = %v, want %v (err %v)", got, tc.wantDeleting, err)
			}
			if resource.OwnedByCaller(err) {
				t.Errorf("err %v reads as BucketAlreadyOwned", err)
			}
			if !tc.wantDeleting && resource.CodeOf(err) != resource.CodeAlreadyExists {
				t.Errorf("foreign name code %v, want AlreadyExists", resource.CodeOf(err))
			}
			if tc.srv.creates != tc.wantCreates {
				t.Errorf("creates sent %d, want %d", tc.srv.creates, tc.wantCreates)
			}
		})
	}
}
