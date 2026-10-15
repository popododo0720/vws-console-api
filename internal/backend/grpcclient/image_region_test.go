package grpcclient

import (
	"context"
	"errors"
	"net"
	"strings"
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

const (
	ownedAMI        = "ami-0123456789abcdef0"
	otherRegionAMI  = "ami-fedcba9876543210"
	absentAMI       = "ami-0000000000000001"
	otherProjectAMI = "ami-abcdefabcdefabcd"
)

type regionalImages struct {
	computev1.UnimplementedInstanceServiceServer
	networkv1.UnimplementedVpcServiceServer
	networkv1.UnimplementedSubnetServiceServer
	storagev1.UnimplementedVolumeServiceServer

	mu        sync.Mutex
	volumes   int
	instances int
	image     string
	labels    map[string]string
}

func (s *regionalImages) ListVpcs(
	_ context.Context, req *networkv1.ListVpcsRequest,
) (*networkv1.ListVpcsResponse, error) {
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	return &networkv1.ListVpcsResponse{Vpcs: []*networkv1.Vpc{{
		Name: vpcName(projectID, "vpc-01234567"),
	}}}, nil
}

func (s *regionalImages) ListSubnets(
	_ context.Context, req *networkv1.ListSubnetsRequest,
) (*networkv1.ListSubnetsResponse, error) {
	return &networkv1.ListSubnetsResponse{Subnets: []*networkv1.Subnet{{
		Name: req.GetParent() + "/subnets/subnet-01234567",
	}}}, nil
}

func (s *regionalImages) CreateVolume(
	_ context.Context, req *storagev1.CreateVolumeRequest,
) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	s.volumes++
	s.image = req.GetVolume().GetSpec().GetImage()
	s.mu.Unlock()
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	return doneNamed(volumeName(projectID, req.GetVolumeId()), commonv1.OperationVerb_OPERATION_VERB_CREATE)
}

func (s *regionalImages) CreateInstance(
	_ context.Context, req *computev1.CreateInstanceRequest,
) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	s.instances++
	s.labels = req.GetInstance().GetLabels()
	s.mu.Unlock()
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	return doneNamed(instanceName(projectID, req.GetInstanceId()), commonv1.OperationVerb_OPERATION_VERB_CREATE)
}

func (s *regionalImages) GetInstance(
	_ context.Context, req *computev1.GetInstanceRequest,
) (*computev1.Instance, error) {
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

func TestRunInstancesRequiresImageInCallerRegion(t *testing.T) {
	caller := project(mustAccount(t))
	ownedName := imageName(caller, ownedAMI)
	sub, err := resource.Parse[resource.SubnetID]("subnet-01234567")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("same project other region", func(t *testing.T) {
		assertImageRefused(t, sub, otherRegionAMI)
	})
	t.Run("absent", func(t *testing.T) {
		assertImageRefused(t, sub, absentAMI)
	})
	t.Run("other project", func(t *testing.T) {
		assertImageRefused(t, sub, otherProjectAMI)
	})
	t.Run("catalog", func(t *testing.T) {
		assertImageLaunches(t, sub, ownedName, "catalog")
	})
	t.Run("owned", func(t *testing.T) {
		assertImageLaunches(t, sub, ownedName, "owned")
	})
}

func assertImageLaunches(t *testing.T, sub resource.SubnetID, ownedName, key string) {
	t.Helper()
	boot, client := startRegional(t)
	acc, err := client.RunInstances(context.Background(), backend.Mutation{
		Scope: backend.Scope{Account: mustAccount(t)}, Key: key, Fingerprint: "fp",
	}, resource.RunInstancesRequest{
		ImageID: mustImage(t, ownedAMI), InstanceType: "vws.small", SubnetID: sub, Count: 1,
	})
	if err != nil || len(acc.Items) != 1 || acc.Items[0].ImageID.String() != ownedAMI {
		t.Fatalf("%v %+v", err, acc.Items)
	}
	boot.mu.Lock()
	defer boot.mu.Unlock()
	if boot.volumes != 1 || boot.instances != 1 || boot.image != ownedName {
		t.Fatalf("volumes %d instances %d image %s", boot.volumes, boot.instances, boot.image)
	}
}

func assertImageRefused(t *testing.T, sub resource.SubnetID, id string) {
	t.Helper()
	boot, client := startRegional(t)
	want := "The image id '[" + id + "]' does not exist"
	for i := 0; i < 2; i++ {
		_, err := client.RunInstances(context.Background(), backend.Mutation{
			Scope: backend.Scope{Account: mustAccount(t)}, Key: "refused-" + id + "-" + string(rune('a'+i)), Fingerprint: "fp",
		}, resource.RunInstancesRequest{
			ImageID: mustImage(t, id), InstanceType: "vws.small", SubnetID: sub, Count: 1,
		})
		var got *resource.Error
		match := errors.As(err, &got) && got.Code == resource.CodeNotFound &&
			got.Kind == resource.KindImage && got.Message == want
		if !match {
			boot.mu.Lock()
			volumes, instances := boot.volumes, boot.instances
			boot.mu.Unlock()
			t.Fatalf("try %d: err %v volumes %d instances %d", i, err, volumes, instances)
		}
		if strings.Contains(got.Message, "projects/") || strings.Contains(got.Message, "vws-2") ||
			strings.Contains(got.Message, "999999999999") {
			t.Fatalf("message %q", got.Message)
		}
	}
	boot.mu.Lock()
	defer boot.mu.Unlock()
	if boot.volumes != 0 || boot.instances != 0 {
		t.Fatalf("volumes %d instances %d", boot.volumes, boot.instances)
	}
}

func startRegional(t *testing.T) (*regionalImages, computeClient) {
	t.Helper()
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	boot := &regionalImages{}
	computev1.RegisterInstanceServiceServer(srv, boot)
	networkv1.RegisterVpcServiceServer(srv, boot)
	networkv1.RegisterSubnetServiceServer(srv, boot)
	storagev1.RegisterVolumeServiceServer(srv, boot)
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
	return boot, client
}
