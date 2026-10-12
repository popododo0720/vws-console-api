package grpcclient

import (
	"context"
	"net"
	"strings"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// storageNotFound is what vws-storage sends for a missing bucket and for a
// missing object alike: NotFound with reason RESOURCE_NOT_FOUND and no kind.
func storageNotFound(msg string) error {
	st, err := status.New(codes.NotFound, msg).WithDetails(&errdetails.ErrorInfo{Reason: "RESOURCE_NOT_FOUND", Domain: "vws.dev"})
	if err != nil {
		panic(err)
	}
	return st.Err()
}

// oneBucket serves a single bucket, "logs", that holds no objects.
type oneBucket struct {
	storagev1.UnimplementedObjectServiceServer
	storagev1.UnimplementedBucketServiceServer
}

func (oneBucket) GetBucket(_ context.Context, req *storagev1.GetBucketRequest) (*storagev1.Bucket, error) {
	if strings.HasSuffix(req.GetName(), "/buckets/logs") {
		return &storagev1.Bucket{Name: req.GetName()}, nil
	}
	return nil, storageNotFound("not found")
}

func (oneBucket) ReadObject(context.Context, *storagev1.ReadObjectRequest) (*storagev1.ReadObjectResponse, error) {
	return nil, storageNotFound("not found")
}

func (oneBucket) DeleteObject(_ context.Context, req *storagev1.DeleteObjectRequest) (*longrunningpb.Operation, error) {
	if strings.Contains(req.GetName(), "/buckets/logs/") {
		return &longrunningpb.Operation{Done: true}, nil
	}
	return nil, storageNotFound("not found")
}

func missingClient(t *testing.T) (storageClient, backend.Scope) {
	t.Helper()
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	storagev1.RegisterObjectServiceServer(srv, oneBucket{})
	storagev1.RegisterBucketServiceServer(srv, oneBucket{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///storage",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return storageClient{&api{
		objects: storagev1.NewObjectServiceClient(conn),
		buckets: storagev1.NewBucketServiceClient(conn),
	}}, backend.Scope{Account: account}
}

func bucketKey(t *testing.T, bucket, key string) (resource.BucketName, resource.ObjectKey) {
	t.Helper()
	b, err := resource.Parse[resource.BucketName](bucket)
	if err != nil {
		t.Fatal(err)
	}
	k, err := resource.Parse[resource.ObjectKey](key)
	if err != nil {
		t.Fatal(err)
	}
	return b, k
}

func wantNotFound(t *testing.T, err error, kind resource.Kind) {
	t.Helper()
	e := resource.AsError(err)
	if err == nil || e.Code != resource.CodeNotFound || e.Kind != kind {
		t.Fatalf("got %v (kind %v), want NotFound kind %v", err, e.Kind, kind)
	}
}

func TestGetMissingObjectIsObjectNotFound(t *testing.T) {
	client, s := missingClient(t)
	b, k := bucketKey(t, "logs", "missing.txt")
	_, _, err := client.GetObject(context.Background(), s, resource.GetObjectRequest{Bucket: b, Key: k})
	wantNotFound(t, err, resource.KindObject)
}

func TestGetObjectInMissingBucketIsBucketNotFound(t *testing.T) {
	client, s := missingClient(t)
	b, k := bucketKey(t, "nobucket", "a.txt")
	_, _, err := client.GetObject(context.Background(), s, resource.GetObjectRequest{Bucket: b, Key: k})
	wantNotFound(t, err, resource.KindBucket)
}

func TestDeleteMissingObjectSucceeds(t *testing.T) {
	client, s := missingClient(t)
	b, k := bucketKey(t, "logs", "missing.txt")
	err := client.DeleteObject(context.Background(), s, b, k)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeleteObjectInMissingBucketIsBucketNotFound(t *testing.T) {
	client, s := missingClient(t)
	b, k := bucketKey(t, "nobucket", "a.txt")
	err := client.DeleteObject(context.Background(), s, b, k)
	wantNotFound(t, err, resource.KindBucket)
}
