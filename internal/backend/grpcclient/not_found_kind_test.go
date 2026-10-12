package grpcclient

import (
	"context"
	"net"
	"testing"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// emptyProject answers every read and delete the way the VWS services do for
// a missing resource: NotFound with reason RESOURCE_NOT_FOUND and no kind.
type emptyProject struct {
	computev1.UnimplementedInstanceServiceServer
	computev1.UnimplementedKeyPairServiceServer
	storagev1.UnimplementedVolumeServiceServer
	storagev1.UnimplementedSnapshotServiceServer
	networkv1.UnimplementedVpcServiceServer
	networkv1.UnimplementedAddressServiceServer
}

func (emptyProject) GetInstance(context.Context, *computev1.GetInstanceRequest) (*computev1.Instance, error) {
	return nil, storageNotFound("not found")
}

func (emptyProject) GetKeyPair(context.Context, *computev1.GetKeyPairRequest) (*computev1.KeyPair, error) {
	return nil, storageNotFound("not found")
}

func (emptyProject) GetVolume(context.Context, *storagev1.GetVolumeRequest) (*storagev1.Volume, error) {
	return nil, storageNotFound("not found")
}

func (emptyProject) GetSnapshot(context.Context, *storagev1.GetSnapshotRequest) (*storagev1.Snapshot, error) {
	return nil, storageNotFound("not found")
}

func (emptyProject) DeleteSnapshot(context.Context, *storagev1.DeleteSnapshotRequest) (*longrunningpb.Operation, error) {
	return nil, storageNotFound("not found")
}

func (emptyProject) GetVpc(context.Context, *networkv1.GetVpcRequest) (*networkv1.Vpc, error) {
	return nil, storageNotFound("not found")
}

func (emptyProject) ListVpcs(context.Context, *networkv1.ListVpcsRequest) (*networkv1.ListVpcsResponse, error) {
	return &networkv1.ListVpcsResponse{}, nil
}

func (emptyProject) GetAddress(context.Context, *networkv1.GetAddressRequest) (*networkv1.Address, error) {
	return nil, storageNotFound("not found")
}

func (emptyProject) DeleteAddress(context.Context, *networkv1.DeleteAddressRequest) (*longrunningpb.Operation, error) {
	return nil, storageNotFound("not found")
}

func emptyClient(t *testing.T) (*api, backend.Mutation) {
	t.Helper()
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	computev1.RegisterInstanceServiceServer(srv, emptyProject{})
	computev1.RegisterKeyPairServiceServer(srv, emptyProject{})
	storagev1.RegisterVolumeServiceServer(srv, emptyProject{})
	storagev1.RegisterSnapshotServiceServer(srv, emptyProject{})
	networkv1.RegisterVpcServiceServer(srv, emptyProject{})
	networkv1.RegisterAddressServiceServer(srv, emptyProject{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///vws",
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
	return &api{
			instances: computev1.NewInstanceServiceClient(conn),
			keys:      computev1.NewKeyPairServiceClient(conn),
			volumes:   storagev1.NewVolumeServiceClient(conn),
			snapshots: storagev1.NewSnapshotServiceClient(conn),
			vpcs:      networkv1.NewVpcServiceClient(conn),
			addresses: networkv1.NewAddressServiceClient(conn),
		}, backend.Mutation{
			Scope: backend.Scope{Account: account}, Key: "k", Fingerprint: "f",
		}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// A missing resource named by the request is reported with its kind, so the
// EC2 surface answers InvalidVolume.NotFound and the like, not
// InvalidParameterValue.
func TestMissingResourceKeepsItsKind(t *testing.T) {
	a, m := emptyClient(t)
	ctx := context.Background()
	compute, network := computeClient{a}, networkClient{a}
	vol := must(resource.Parse[resource.VolumeID]("vol-0123456789abcdef0"))
	snap := must(resource.Parse[resource.SnapshotID]("snap-0123456789abcdef0"))
	inst := must(resource.Parse[resource.InstanceID]("i-0123456789abcdef0"))
	vpc := must(resource.Parse[resource.VpcID]("vpc-0123456789abcdef0"))
	addr := must(resource.Parse[resource.AddressID]("eipalloc-0123456789abcdef0"))
	sub := must(resource.Parse[resource.SubnetID]("subnet-0123456789abcdef0"))
	for _, tc := range []struct {
		name string
		kind resource.Kind
		call func() error
	}{
		{"CreateSnapshot", resource.KindVolume, func() error {
			_, err := compute.CreateSnapshot(ctx, m, resource.CreateSnapshotRequest{VolumeID: vol})
			return err
		}},
		{"DeleteVolume", resource.KindVolume, func() error {
			_, err := compute.DeleteVolume(ctx, m, resource.DeleteVolumeRequest{ID: vol})
			return err
		}},
		{"AttachVolume", resource.KindVolume, func() error {
			_, err := compute.AttachVolume(ctx, m, resource.AttachVolumeRequest{VolumeID: vol, InstanceID: inst, Device: "/dev/sdf"})
			return err
		}},
		{"DeleteSnapshot", resource.KindSnapshot, func() error {
			_, err := compute.DeleteSnapshot(ctx, m, resource.DeleteSnapshotRequest{ID: snap})
			return err
		}},
		{"StopInstances", resource.KindInstance, func() error {
			_, err := compute.StopInstances(ctx, m, resource.StopInstancesRequest{IDs: []resource.InstanceID{inst}})
			return err
		}},
		{"StartInstances", resource.KindInstance, func() error {
			_, err := compute.StartInstances(ctx, m, resource.StartInstancesRequest{IDs: []resource.InstanceID{inst}})
			return err
		}},
		{"TerminateInstances", resource.KindInstance, func() error {
			_, err := compute.TerminateInstances(ctx, m, resource.TerminateInstancesRequest{IDs: []resource.InstanceID{inst}})
			return err
		}},
		{"DeleteVpc", resource.KindVpc, func() error {
			_, err := network.DeleteVpc(ctx, m, resource.DeleteVpcRequest{ID: vpc})
			return err
		}},
		{"ReleaseAddress", resource.KindAddress, func() error {
			_, err := network.ReleaseAddress(ctx, m, resource.ReleaseAddressRequest{ID: addr})
			return err
		}},
		{"DeleteSubnet", resource.KindSubnet, func() error {
			_, err := network.DeleteSubnet(ctx, m, resource.DeleteSubnetRequest{ID: sub})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := resource.AsError(tc.call())
			if e == nil || e.Code != resource.CodeNotFound || e.Kind != tc.kind {
				t.Fatalf("err = %#v, want NotFound of kind %v", e, tc.kind)
			}
		})
	}
}
