package grpcclient

import (
	"context"
	"net"
	"sync"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// twentyHex is the operation width vws-storage and vws-compute publish.
const twentyHex = "0123456789abcdef0123"

// widthVolume returns the operation name those services publish, op- plus 20
// hex digits, and keeps the volume id of the first request.
type widthVolume struct {
	storagev1.UnimplementedVolumeServiceServer
	mu sync.Mutex
	id string
}

func (s *widthVolume) CreateVolume(_ context.Context, req *storagev1.CreateVolumeRequest) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.id == "" {
		s.id = req.GetVolumeId()
	}
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	meta, err := anypb.New(&commonv1.OperationMetadata{
		Resource:   volumeName(projectID, s.id),
		Verb:       commonv1.OperationVerb_OPERATION_VERB_CREATE,
		CreateTime: timestamppb.Now(),
	})
	if err != nil {
		return nil, toStatus(resource.Internal(err))
	}
	return &longrunningpb.Operation{
		Name:     "projects/" + projectID + "/operations/op-" + twentyHex,
		Metadata: meta,
		Done:     true,
	}, nil
}

func TestCreateVolumeRetryKeepsTheVolumeID(t *testing.T) {
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	storagev1.RegisterVolumeServiceServer(srv, &widthVolume{})
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
	client := computeClient{&api{volumes: storagev1.NewVolumeServiceClient(conn)}}
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	m := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "vol-token", Fingerprint: "fp"}
	req := resource.CreateVolumeRequest{SizeGiB: 8, Zone: resource.ZoneName, Type: resource.VolumeGP2}
	first, err := client.CreateVolume(context.Background(), m, req)
	if err != nil {
		t.Fatal(err)
	}
	if got := first.Operation.ID.Local(); got != twentyHex {
		t.Fatalf("operation %s", got)
	}
	again, err := client.CreateVolume(context.Background(), m, req)
	if err != nil {
		t.Fatal(err)
	}
	if again.Items[0].ID != first.Items[0].ID || again.Items[0].ID.IsZero() {
		t.Fatalf("retry %s want %s", again.Items[0].ID, first.Items[0].ID)
	}
}
