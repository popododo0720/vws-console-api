package grpcclient

import (
	"context"
	"net"
	"sync"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// imageBoot records the volume source RunInstances sends. The subnet exists
// so the call reaches CreateVolume.
type imageBoot struct {
	networkv1.UnimplementedVpcServiceServer
	networkv1.UnimplementedSubnetServiceServer
	storagev1.UnimplementedVolumeServiceServer
	computev1.UnimplementedInstanceServiceServer
	mu     sync.Mutex
	labels map[string]string
	image  string
	source string
}

func (s *imageBoot) ListVpcs(_ context.Context, req *networkv1.ListVpcsRequest) (*networkv1.ListVpcsResponse, error) {
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	return &networkv1.ListVpcsResponse{Vpcs: []*networkv1.Vpc{{
		Name: vpcName(projectID, "vpc-01234567"),
	}}}, nil
}

func (s *imageBoot) ListSubnets(_ context.Context, req *networkv1.ListSubnetsRequest) (*networkv1.ListSubnetsResponse, error) {
	return &networkv1.ListSubnetsResponse{Subnets: []*networkv1.Subnet{{
		Name: req.GetParent() + "/subnet-01234567",
	}}}, nil
}

func (s *imageBoot) CreateVolume(_ context.Context, req *storagev1.CreateVolumeRequest) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	spec := req.GetVolume().GetSpec()
	s.image = spec.GetImage()
	switch spec.GetSource().(type) {
	case *storagev1.VolumeSpec_Image:
		s.source = "image"
	case *storagev1.VolumeSpec_Snapshot:
		s.source = "snapshot"
	default:
		s.source = ""
	}
	s.mu.Unlock()
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	return doneNamed(volumeName(projectID, req.GetVolumeId()), commonv1.OperationVerb_OPERATION_VERB_CREATE)
}

func (s *imageBoot) CreateInstance(_ context.Context, req *computev1.CreateInstanceRequest) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	s.labels = req.GetInstance().GetLabels()
	s.mu.Unlock()
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	return doneNamed(instanceName(projectID, req.GetInstanceId()), commonv1.OperationVerb_OPERATION_VERB_CREATE)
}

// GetInstance returns the labels CreateInstance stored, as the real service
// does. The test must not add labels the caller did not send.
func (s *imageBoot) GetInstance(_ context.Context, req *computev1.GetInstanceRequest) (*computev1.Instance, error) {
	s.mu.Lock()
	labels := s.labels
	s.mu.Unlock()
	return &computev1.Instance{
		Name:   req.GetName(),
		Labels: labels,
		Spec: &computev1.InstanceSpec{
			MachineType: "vws.small",
			Power:       computev1.InstancePower_INSTANCE_POWER_RUNNING,
			NetworkInterfaces: []*computev1.NetworkInterface{{
				DeviceName: "nic0",
				Subnet:     "projects/a123456789012/regions/" + resource.RegionName + "/vpcs/vpc-01234567/subnets/subnet-01234567",
			}},
		},
		Status: &computev1.InstanceStatus{
			Observed: &commonv1.ObservedState{State: commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING},
			Power:    computev1.InstancePower_INSTANCE_POWER_RUNNING,
		},
	}, nil
}

func TestBootVolumeSourcesTheImage(t *testing.T) {
	const imageID = "ami-0123456789abcdef0"
	projectID := project(mustAccount(t))
	vol := bootVolume(projectID, "fp", mustImage(t, imageID))
	if vol.GetSpec().GetImage() != imageName(projectID, imageID) || vol.GetSpec().GetSnapshot() != "" {
		t.Fatalf("spec %+v", vol.GetSpec())
	}

	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	boot := &imageBoot{}
	networkv1.RegisterVpcServiceServer(srv, boot)
	networkv1.RegisterSubnetServiceServer(srv, boot)
	storagev1.RegisterVolumeServiceServer(srv, boot)
	computev1.RegisterInstanceServiceServer(srv, boot)
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
	client := computeClient{&api{
		instances: computev1.NewInstanceServiceClient(conn),
		volumes:   storagev1.NewVolumeServiceClient(conn),
		subnets:   networkv1.NewSubnetServiceClient(conn),
		vpcs:      networkv1.NewVpcServiceClient(conn),
	}}
	sub, err := resource.Parse[resource.SubnetID]("subnet-01234567")
	if err != nil {
		t.Fatal(err)
	}
	acc, err := client.RunInstances(context.Background(), backend.Mutation{
		Scope: backend.Scope{Account: mustAccount(t)}, Key: "run-1", Fingerprint: "fp",
	}, resource.RunInstancesRequest{
		ImageID: mustImage(t, imageID), InstanceType: "vws.small", SubnetID: sub, Count: 1,
	})
	if err != nil || len(acc.Items) != 1 {
		t.Fatalf("%v %+v", err, acc.Items)
	}
	boot.mu.Lock()
	gotImage, gotSource := boot.image, boot.source
	boot.mu.Unlock()
	if gotSource != "image" || gotImage != imageName(projectID, imageID) {
		t.Fatalf("source %s image %s", gotSource, gotImage)
	}
}

func mustAccount(t *testing.T) resource.AccountID {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return account
}

func mustImage(t *testing.T, id string) resource.ImageID {
	t.Helper()
	image, err := resource.Parse[resource.ImageID](id)
	if err != nil {
		t.Fatal(err)
	}
	return image
}
