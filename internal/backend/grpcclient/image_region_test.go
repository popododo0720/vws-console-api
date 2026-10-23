package grpcclient

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

const (
	catalogAMI      = "ami-0123456789abcdef0"
	registeredAMI   = "ami-0a1b2c3d4e5f67890"
	otherRegionAMI  = "ami-fedcba9876543210"
	absentAMI       = "ami-0000000000000001"
	otherProjectAMI = "ami-abcdefabcdefabcd"
	otherProjectID  = "a999999999999"
	otherRegionName = "vws-2"
)

// imageRecord is an image as compute stores it: owned by one project and
// copied into one region. A read resolves the requested name against this
// stored scope; the requested name itself proves nothing.
type imageRecord struct {
	project string
	region  string
}

type regionalImages struct {
	computev1.UnimplementedInstanceServiceServer
	computev1.UnimplementedImageServiceServer
	networkv1.UnimplementedVpcServiceServer
	networkv1.UnimplementedSubnetServiceServer
	storagev1.UnimplementedVolumeServiceServer

	mu         sync.Mutex
	volumes    int
	instances  int
	image      string
	labels     map[string]string
	images     map[string]imageRecord
	imageReads int
	imageName  string
	imageDown  bool
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

func (s *regionalImages) GetImage(
	_ context.Context, req *computev1.GetImageRequest,
) (*computev1.Image, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.imageReads++
	s.imageName = req.GetName()
	if s.imageDown {
		return nil, status.Error(codes.Unavailable, "image store down")
	}
	projectID, region, id, ok := imagePath(req.GetName())
	stored, found := s.images[id]
	if !ok || !found || stored.project != projectID || stored.region != region {
		return nil, status.Error(codes.NotFound, "image "+req.GetName()+" not found")
	}
	return &computev1.Image{Name: req.GetName()}, nil
}

// imagePath splits a compute image resource name into its stored scope.
func imagePath(name string) (projectID, region, id string, ok bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != "regions" || parts[4] != "images" {
		return "", "", "", false
	}
	return parts[1], parts[3], parts[5], true
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
	sub, err := resource.Parse[resource.SubnetID]("subnet-01234567")
	if err != nil {
		t.Fatal(err)
	}
	caller := project(mustAccount(t))

	t.Run("registered in region", func(t *testing.T) {
		boot, client := startRegional(t)
		assertImageLaunches(t, boot, client, sub, registeredAMI, "registered")
		if boot.imageReads != 1 || boot.imageName != imageName(caller, registeredAMI) {
			t.Fatalf("reads %d name %q", boot.imageReads, boot.imageName)
		}
	})
	t.Run("catalog", func(t *testing.T) {
		boot, client := startRegional(t)
		assertImageLaunches(t, boot, client, sub, catalogAMI, "catalog")
		if boot.imageReads != 0 {
			t.Fatalf("catalog read the image store %d times", boot.imageReads)
		}
	})
	t.Run("catalog without image store", func(t *testing.T) {
		boot, client := startRegional(t)
		boot.mu.Lock()
		boot.imageDown = true
		boot.mu.Unlock()
		assertImageLaunches(t, boot, client, sub, catalogAMI, "catalog-down")
		if boot.imageReads != 0 {
			t.Fatalf("catalog read the image store %d times", boot.imageReads)
		}
	})
	t.Run("same project other region", func(t *testing.T) {
		assertImageRefused(t, sub, otherRegionAMI)
	})
	t.Run("other project", func(t *testing.T) {
		assertImageRefused(t, sub, otherProjectAMI)
	})
	t.Run("absent", func(t *testing.T) {
		assertImageRefused(t, sub, absentAMI)
	})
	t.Run("image store down", func(t *testing.T) {
		boot, client := startRegional(t)
		boot.mu.Lock()
		boot.imageDown = true
		boot.mu.Unlock()
		for i := 0; i < 2; i++ {
			_, err := launchImage(t, client, sub, registeredAMI, "down-"+strconv.Itoa(i))
			if resource.CodeOf(err) != resource.CodeUnavailable {
				t.Fatalf("try %d: %v, want unavailable", i, err)
			}
		}
		if boot.imageReads != 2 || boot.volumes != 0 || boot.instances != 0 {
			t.Fatalf("reads %d volumes %d instances %d", boot.imageReads, boot.volumes, boot.instances)
		}
	})
}

func launchImage(
	t *testing.T, client computeClient, sub resource.SubnetID, id, key string,
) (resource.Accepted[resource.Instance], error) {
	t.Helper()
	return client.RunInstances(context.Background(), backend.Mutation{
		Scope: backend.Scope{Account: mustAccount(t)}, Key: key, Fingerprint: "fp",
	}, resource.RunInstancesRequest{
		ImageID: mustImage(t, id), InstanceType: "vws.small", SubnetID: sub, Count: 1,
	})
}

func assertImageLaunches(
	t *testing.T, boot *regionalImages, client computeClient, sub resource.SubnetID, id, key string,
) {
	t.Helper()
	acc, err := launchImage(t, client, sub, id, key)
	if err != nil || len(acc.Items) != 1 || acc.Items[0].ImageID.String() != id {
		t.Fatalf("%v %+v", err, acc.Items)
	}
	want := imageName(project(mustAccount(t)), id)
	boot.mu.Lock()
	defer boot.mu.Unlock()
	if boot.volumes != 1 || boot.instances != 1 || boot.image != want {
		t.Fatalf("volumes %d instances %d image %q want %q", boot.volumes, boot.instances, boot.image, want)
	}
}

// assertImageRefused checks that compute's stored scope refuses the image on
// every try and that neither a volume nor an instance is created.
func assertImageRefused(t *testing.T, sub resource.SubnetID, id string) {
	t.Helper()
	boot, client := startRegional(t)
	caller := imageName(project(mustAccount(t)), id)
	want := "The image id '[" + id + "]' does not exist"
	for i := 0; i < 2; i++ {
		_, err := launchImage(t, client, sub, id, "refused-"+id+"-"+strconv.Itoa(i))
		var got *resource.Error
		match := errors.As(err, &got) && got.Code == resource.CodeNotFound &&
			got.Kind == resource.KindImage && got.Message == want
		if !match {
			boot.mu.Lock()
			volumes, instances := boot.volumes, boot.instances
			boot.mu.Unlock()
			t.Fatalf("try %d: err %v volumes %d instances %d", i, err, volumes, instances)
		}
		if strings.Contains(got.Message, "projects/") || strings.Contains(got.Message, otherRegionName) ||
			strings.Contains(got.Message, otherProjectID) {
			t.Fatalf("message %q", got.Message)
		}
	}
	boot.mu.Lock()
	defer boot.mu.Unlock()
	if boot.volumes != 0 || boot.instances != 0 {
		t.Fatalf("volumes %d instances %d", boot.volumes, boot.instances)
	}
	if boot.imageReads != 2 || boot.imageName != caller {
		t.Fatalf("reads %d name %q want %q", boot.imageReads, boot.imageName, caller)
	}
}

func startRegional(t *testing.T) (*regionalImages, computeClient) {
	t.Helper()
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	caller := project(mustAccount(t))
	boot := &regionalImages{images: map[string]imageRecord{
		registeredAMI:   {project: caller, region: resource.RegionName},
		otherRegionAMI:  {project: caller, region: otherRegionName},
		otherProjectAMI: {project: otherProjectID, region: resource.RegionName},
	}}
	computev1.RegisterInstanceServiceServer(srv, boot)
	computev1.RegisterImageServiceServer(srv, boot)
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
		images:    computev1.NewImageServiceClient(conn),
		volumes:   storagev1.NewVolumeServiceClient(conn),
		subnets:   networkv1.NewSubnetServiceClient(conn),
		vpcs:      networkv1.NewVpcServiceClient(conn),
	}}
	return boot, client
}
