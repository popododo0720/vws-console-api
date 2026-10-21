package grpcclient

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// invalidNameWorld serves one readable instance and volume beside one record
// whose resource name is not a resource id.
type invalidNameWorld struct {
	computev1.UnimplementedInstanceServiceServer
	storagev1.UnimplementedVolumeServiceServer
	inst []*computev1.Instance
	vol  []*storagev1.Volume
}

func (s *invalidNameWorld) ListInstances(
	context.Context, *computev1.ListInstancesRequest,
) (*computev1.ListInstancesResponse, error) {
	return &computev1.ListInstancesResponse{Instances: s.inst}, nil
}

func (s *invalidNameWorld) GetInstance(
	_ context.Context, req *computev1.GetInstanceRequest,
) (*computev1.Instance, error) {
	for _, inst := range s.inst {
		if lastSegment(inst.GetName()) == lastSegment(req.GetName()) {
			return inst, nil
		}
	}
	return nil, status.Error(codes.NotFound, "missing instance")
}

func (s *invalidNameWorld) ListVolumes(
	context.Context, *storagev1.ListVolumesRequest,
) (*storagev1.ListVolumesResponse, error) {
	return &storagev1.ListVolumesResponse{Volumes: s.vol}, nil
}

func (s *invalidNameWorld) GetVolume(
	_ context.Context, req *storagev1.GetVolumeRequest,
) (*storagev1.Volume, error) {
	for _, vol := range s.vol {
		if lastSegment(vol.GetName()) == lastSegment(req.GetName()) {
			return vol, nil
		}
	}
	return nil, status.Error(codes.NotFound, "missing volume")
}

func dialInvalidNameWorld(t *testing.T, world *invalidNameWorld) (computeClient, *bytes.Buffer) {
	t.Helper()
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	computev1.RegisterInstanceServiceServer(srv, world)
	storagev1.RegisterVolumeServiceServer(srv, world)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///compute",
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
		instances: computev1.NewInstanceServiceClient(conn),
		volumes:   storagev1.NewVolumeServiceClient(conn),
		log:       slog.New(slog.NewTextHandler(&logs, nil)),
	}}, &logs
}

func TestInvalidResourceNameIsSkippedInList(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const goodInstanceID = "i-0123456789abcdef0"
	const badInstanceID = "i-0fedcba9876543210"
	const goodVolumeID = "vol-0123456789abcdef0"
	const badVolumeID = "vol-0fedcba9876543210"
	badInstance := observedInstance(projectID, badInstanceID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		computev1.InstancePower_INSTANCE_POWER_RUNNING)
	badInstance.Name = "projects/" + projectID + "/instances/" + badInstanceID
	badVolume := observedVolume(projectID, badVolumeID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY, "")
	badVolume.Name = "projects/" + projectID + "/volumes/" + badVolumeID
	world := &invalidNameWorld{
		inst: []*computev1.Instance{
			observedInstance(projectID, goodInstanceID,
				commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
				computev1.InstancePower_INSTANCE_POWER_RUNNING),
			badInstance,
		},
		vol: []*storagev1.Volume{
			observedVolume(projectID, goodVolumeID,
				commonv1.ReconciliationState_RECONCILIATION_STATE_READY, ""),
			badVolume,
		},
	}
	client, logs := dialInvalidNameWorld(t, world)
	ctx := context.Background()
	scope := backend.Scope{Account: account}

	instances, err := client.DescribeInstances(ctx, scope, resource.InstanceQuery{})
	if err != nil {
		t.Fatalf("DescribeInstances: %v", err)
	}
	if len(instances.Items) != 1 || instances.Items[0].ID.String() != goodInstanceID {
		t.Fatalf("instances %+v", instances.Items)
	}

	volumes, err := client.DescribeVolumes(ctx, scope, resource.VolumeQuery{})
	if err != nil {
		t.Fatalf("DescribeVolumes: %v", err)
	}
	if len(volumes.Items) != 1 || volumes.Items[0].ID.String() != goodVolumeID {
		t.Fatalf("volumes %+v", volumes.Items)
	}
	if !strings.Contains(logs.String(), badInstance.GetName()) ||
		!strings.Contains(logs.String(), badVolume.GetName()) {
		t.Fatalf("logs %s", logs.String())
	}

	badInstanceIDParsed, err := resource.Parse[resource.InstanceID](badInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DescribeInstances(ctx, scope, resource.InstanceQuery{
		IDs: []resource.InstanceID{badInstanceIDParsed},
	})
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("explicit instance read: %v", err)
	}

	badVolumeIDParsed, err := resource.Parse[resource.VolumeID](badVolumeID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DescribeVolumes(ctx, scope, resource.VolumeQuery{
		IDs: []resource.VolumeID{badVolumeIDParsed},
	})
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("explicit volume read: %v", err)
	}
}
