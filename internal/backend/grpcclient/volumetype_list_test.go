package grpcclient

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// unknownTypeWorld is invalidNameWorld's volume side, whose DeleteVolume
// accepts any listed volume and records the names it deleted.
type unknownTypeWorld struct {
	invalidNameWorld
	mu      sync.Mutex
	deleted []string
}

func (s *unknownTypeWorld) DeleteVolume(
	_ context.Context, req *storagev1.DeleteVolumeRequest,
) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = append(s.deleted, req.GetName())
	projectID := strings.Split(req.GetName(), "/")[1]
	return &longrunningpb.Operation{
		Name: "projects/" + projectID + "/operations/op-" + twentyHex, Done: true,
	}, nil
}

func dialUnknownTypeWorld(t *testing.T, world *unknownTypeWorld) (computeClient, *bytes.Buffer) {
	t.Helper()
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	storagev1.RegisterVolumeServiceServer(srv, world)
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
	var logs bytes.Buffer
	return computeClient{&api{
		volumes: storagev1.NewVolumeServiceClient(conn),
		log:     slog.New(slog.NewJSONHandler(&logs, nil)),
	}}, &logs
}

// #335 r1: a stored volume whose type this build cannot name (UNSPECIFIED,
// or a number a later vws-proto added) is left out of a DescribeVolumes
// listing and logged by name, so it does not fail the listing for every
// other volume. An explicit id read still answers Internal, never a guessed
// gp2, and DeleteVolume still reaches the volume so it can be cleaned up.
func TestVolumeWithUnknownTypeIsSkippedInList(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const goodID = "vol-0123456789abcdef0"
	bad := map[string]storagev1.VolumeType{
		"vol-0fedcba9876543210": storagev1.VolumeType_VOLUME_TYPE_UNSPECIFIED,
		"vol-0aaaaaaaaaaaaaaa0": storagev1.VolumeType(99),
	}
	ready := commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	world := &unknownTypeWorld{}
	world.vol = append(world.vol, observedVolume(projectID, goodID, ready, ""))
	for id, typ := range bad {
		v := observedVolume(projectID, id, ready, "")
		v.Spec.Type = typ
		world.vol = append(world.vol, v)
	}
	client, logs := dialUnknownTypeWorld(t, world)
	ctx := context.Background()
	scope := backend.Scope{Account: account}

	volumes, err := client.DescribeVolumes(ctx, scope, resource.VolumeQuery{})
	switch {
	case err != nil:
		t.Errorf("DescribeVolumes: %v", err)
	case len(volumes.Items) != 1 || volumes.Items[0].ID.String() != goodID ||
		volumes.Items[0].Type != resource.VolumeGP2:
		t.Errorf("volumes %+v, want only %s", volumes.Items, goodID)
	}
	for id, typ := range bad {
		name := volumeName(projectID, id)
		if !strings.Contains(logs.String(), `"name":"`+name+`"`) ||
			!strings.Contains(logs.String(), typ.String()) {
			t.Errorf("no log record names %s with type %s: %s", name, typ, logs.String())
		}
	}

	for id := range bad {
		vid, err := resource.Parse[resource.VolumeID](id)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.DescribeVolumes(ctx, scope, resource.VolumeQuery{IDs: []resource.VolumeID{vid}})
		if resource.CodeOf(err) != resource.CodeInternal {
			t.Errorf("explicit read of %s: %v, want Internal", id, err)
		}
		acc, err := client.DeleteVolume(ctx, backend.Mutation{Scope: scope, Key: "delete-" + id},
			resource.DeleteVolumeRequest{ID: vid})
		if err != nil {
			t.Errorf("DeleteVolume %s: %v", id, err)
			continue
		}
		if len(acc.Items) != 1 || acc.Items[0].ID != vid || acc.Items[0].State != resource.VolumeDeleting {
			t.Errorf("DeleteVolume %s accepted %+v", id, acc.Items)
		}
	}
	world.mu.Lock()
	defer world.mu.Unlock()
	if len(world.deleted) != len(bad) {
		t.Fatalf("storage deleted %q, want the %d volumes with an unknown type", world.deleted, len(bad))
	}
}
