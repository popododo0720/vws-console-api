package grpcclient

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// mintedImage is the id compute gives the copy, whatever image_id said.
const mintedImage = "img-0123456789abcdef0"

type registerSrv struct {
	computev1.UnimplementedImageServiceServer
	storagev1.UnimplementedSnapshotServiceServer
	mu        sync.Mutex
	snapshot  *storagev1.Snapshot
	snapErr   error
	snapNames []string
	creates   []*computev1.CreateImageRequest
}

func (s *registerSrv) GetSnapshot(_ context.Context, req *storagev1.GetSnapshotRequest) (*storagev1.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapNames = append(s.snapNames, req.GetName())
	if s.snapErr != nil {
		return nil, s.snapErr
	}
	return s.snapshot, nil
}

func (s *registerSrv) CreateImage(
	_ context.Context, req *computev1.CreateImageRequest,
) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creates = append(s.creates, proto.CloneOf(req))
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	return longOp(projectID, "0123456789abcdef0123", imageName(projectID, mintedImage), req.GetRequestId(),
		commonv1.OperationVerb_OPERATION_VERB_CREATE, time.Unix(1_794_000_000, 0))
}

func startRegister(t *testing.T, srv *registerSrv) computeClient {
	t.Helper()
	lis := bufconn.Listen(MaxMessageBytes())
	server := grpc.NewServer()
	computev1.RegisterImageServiceServer(server, srv)
	storagev1.RegisterSnapshotServiceServer(server, srv)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///register",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return computeClient{&api{
		images: computev1.NewImageServiceClient(conn), snapshots: storagev1.NewSnapshotServiceClient(conn),
	}}
}

func registerFixture(t *testing.T, state string) (resource.AccountID, resource.RegisterImageRequest, *registerSrv) {
	t.Helper()
	account := mustAccount(t)
	snap, err := resource.Parse[resource.SnapshotID]("snap-0a1b2c3d4e5f60718")
	if err != nil {
		t.Fatal(err)
	}
	vol, err := resource.Parse[resource.VolumeID]("vol-0a1b2c3d4e5f60718")
	if err != nil {
		t.Fatal(err)
	}
	srv := &registerSrv{snapshot: snapshotProto(resource.Snapshot{
		ID: snap, OwnerID: account, VolumeID: vol, VolumeSize: 16, State: state,
	}, project(account))}
	return account, resource.RegisterImageRequest{Name: "web", Description: "nightly", SnapshotID: snap}, srv
}

func TestRegisterImageAnswersTheImageComputeMinted(t *testing.T) {
	account, req, srv := registerFixture(t, resource.SnapshotCompleted)
	client := startRegister(t, srv)
	mut := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "key-1", Fingerprint: "fp-1"}
	acc, err := client.RegisterImage(context.Background(), mut, req)
	if err != nil {
		t.Fatal(err)
	}
	if got := acc.Items[0]; got.ID.String() != "ami-0123456789abcdef0" || got.OwnerID != account ||
		got.Name != "web" || got.SizeGiB != 16 || got.State != resource.ImagePending {
		t.Fatalf("image %+v", got)
	}
	if acc.Operation.Action != resource.ActionRegisterImage || acc.Operation.Targets[0] != acc.Items[0].ID.Ref() {
		t.Fatalf("operation %+v", acc.Operation)
	}
	if len(srv.creates) != 1 {
		t.Fatalf("creates %d", len(srv.creates))
	}
	sent := srv.creates[0]
	spec := sent.GetImage().GetSpec()
	if sent.GetParent() != regionParent(project(account)) ||
		spec.GetSnapshot() != snapshotName(project(account), req.SnapshotID.String()) ||
		spec.GetFamily() != "web" || spec.GetDescription() != "nightly" ||
		sent.GetRequestId() != requestUUID("key-1", "image") {
		t.Fatalf("create %v", sent)
	}
	if len(srv.snapNames) != 1 || srv.snapNames[0] != snapshotName(project(account), req.SnapshotID.String()) {
		t.Fatalf("snapshot read %v", srv.snapNames)
	}
}

func TestRegisterImageRefusesAPendingSnapshot(t *testing.T) {
	account, req, srv := registerFixture(t, resource.SnapshotPending)
	client := startRegister(t, srv)
	_, err := client.RegisterImage(context.Background(), backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: "key-1", Fingerprint: "fp-1",
	}, req)
	var got *resource.Error
	if !errors.As(err, &got) || got.Code != resource.CodeConflict || got.Kind != resource.KindSnapshot ||
		got.ID != req.SnapshotID.String() {
		t.Fatalf("pending snapshot: %v", err)
	}
	if len(srv.creates) != 0 {
		t.Fatalf("compute was asked to copy a pending snapshot: %v", srv.creates)
	}
}

func TestRegisterImageOfAMissingSnapshotIsSnapshotNotFound(t *testing.T) {
	account, req, srv := registerFixture(t, resource.SnapshotCompleted)
	srv.snapErr = status.Error(codes.NotFound, "snapshot not found")
	client := startRegister(t, srv)
	_, err := client.RegisterImage(context.Background(), backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: "key-1", Fingerprint: "fp-1",
	}, req)
	var got *resource.Error
	if !errors.As(err, &got) || got.Code != resource.CodeNotFound || got.Kind != resource.KindSnapshot {
		t.Fatalf("missing snapshot: %v", err)
	}
	if len(srv.creates) != 0 {
		t.Fatalf("compute was asked to copy a missing snapshot: %v", srv.creates)
	}
}
