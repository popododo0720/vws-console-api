package grpcclient

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// pendingObject hides the object until its operation is polled. A client that
// calls GetObject first sees NotFound.
type pendingObject struct {
	storagev1.UnimplementedObjectServiceServer
	longrunningpb.UnimplementedOperationsServer
	mu     sync.Mutex
	ready  bool
	name   string
	size   int64
	sha256 string
}

func (s *pendingObject) UpdateObject(_ context.Context, req *storagev1.UpdateObjectRequest) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = false
	s.name = req.GetObject().GetName()
	s.size = int64(len(req.GetContents()))
	s.sha256 = req.GetObject().GetSpec().GetSha256()
	projectID, err := projectOfName(s.name)
	if err != nil {
		return nil, toStatus(err)
	}
	meta, err := anypb.New(&commonv1.OperationMetadata{
		Resource:   s.name,
		Verb:       commonv1.OperationVerb_OPERATION_VERB_UPDATE,
		CreateTime: timestamppb.Now(),
	})
	if err != nil {
		return nil, toStatus(resource.Internal(err))
	}
	return &longrunningpb.Operation{
		Name:     operationName(projectID, "0123456789abcdef"),
		Metadata: meta,
	}, nil
}

func (s *pendingObject) GetOperation(_ context.Context, req *longrunningpb.GetOperationRequest) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = true
	return &longrunningpb.Operation{Name: req.GetName(), Done: true}, nil
}

func (s *pendingObject) GetObject(_ context.Context, req *storagev1.GetObjectRequest) (*storagev1.Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready || req.GetName() != s.name {
		return nil, status.Error(codes.NotFound, "object")
	}
	return &storagev1.Object{
		Name:   s.name,
		Spec:   &storagev1.ObjectSpec{ContentType: "text/plain", Sha256: s.sha256},
		Status: &storagev1.ObjectStatus{SizeBytes: s.size, Md5: "5d41402abc4b2a76b9719d911017c592"},
	}, nil
}

func TestPutObjectWaitsForTheOperation(t *testing.T) {
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	pending := &pendingObject{}
	storagev1.RegisterObjectServiceServer(srv, pending)
	longrunningpb.RegisterOperationsServer(srv, pending)
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
	client := storageClient{&api{
		objects:    storagev1.NewObjectServiceClient(conn),
		storageOps: longrunningpb.NewOperationsClient(conn),
	}}
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	bucket, err := resource.Parse[resource.BucketName]("logs")
	if err != nil {
		t.Fatal(err)
	}
	key, err := resource.Parse[resource.ObjectKey]("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	obj, err := client.PutObject(context.Background(), backend.Scope{Account: account}, resource.PutObjectRequest{
		Bucket: bucket, Key: key, ContentType: "text/plain", Size: 5,
	}, strings.NewReader("hello"))
	if err != nil || obj.Size != 5 || obj.Key != key || obj.ETag != `"5d41402abc4b2a76b9719d911017c592"` {
		t.Fatalf("%v %+v", err, obj)
	}
	// The put names the payload hash in spec.sha256 so vws-storage stores
	// it with the object, and the object read back carries it.
	const helloSHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if pending.sha256 != helloSHA256 || obj.SHA256 != helloSHA256 {
		t.Fatalf("spec.sha256 sent %q, object %q, want %s", pending.sha256, obj.SHA256, helloSHA256)
	}
}
