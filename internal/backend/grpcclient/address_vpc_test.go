package grpcclient

import (
	"context"
	"net"
	"strconv"
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
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// vpcGate is the network check at grpcapi/server.go: the address proto has no
// VPC field, and CreateAddress is InvalidArgument until the project has a VPC.
type vpcGate struct {
	networkv1.UnimplementedVpcServiceServer
	networkv1.UnimplementedAddressServiceServer
	mu   sync.Mutex
	cidr string
}

func (s *vpcGate) ListVpcs(context.Context, *networkv1.ListVpcsRequest) (*networkv1.ListVpcsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cidr == "" {
		return &networkv1.ListVpcsResponse{}, nil
	}
	return &networkv1.ListVpcsResponse{Vpcs: []*networkv1.Vpc{{
		Name: "projects/p/regions/" + resource.RegionName + "/vpcs/vpc-01234567",
		Spec: &networkv1.VpcSpec{Ipv4Cidr: s.cidr},
	}}}, nil
}

func (s *vpcGate) CreateVpc(_ context.Context, req *networkv1.CreateVpcRequest) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cidr = req.GetVpc().GetSpec().GetIpv4Cidr()
	return doneNamed(req.GetParent()+"/vpcs/"+req.GetVpcId(), commonv1.OperationVerb_OPERATION_VERB_CREATE)
}

func (s *vpcGate) CreateAddress(_ context.Context, req *networkv1.CreateAddressRequest) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cidr == "" {
		return nil, status.Error(codes.InvalidArgument, "vpc is required")
	}
	if req.GetAddress().GetSpec().GetVpc() == "" {
		return nil, status.Error(codes.InvalidArgument, "an address is allocated in a vpc")
	}
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	return doneNamed(addressName(projectID, req.GetAddressId()), commonv1.OperationVerb_OPERATION_VERB_CREATE)
}

func doneNamed(resourceName string, verb commonv1.OperationVerb) (*longrunningpb.Operation, error) {
	projectID, err := projectOfName(resourceName)
	if err != nil {
		return nil, toStatus(err)
	}
	meta, err := anypb.New(&commonv1.OperationMetadata{
		Resource:   resourceName,
		Verb:       verb,
		CreateTime: timestamppb.Now(),
	})
	if err != nil {
		return nil, toStatus(resource.Internal(err))
	}
	return &longrunningpb.Operation{
		Name:     operationName(projectID, "0123456789abcdef"),
		Metadata: meta,
		Done:     true,
	}, nil
}

func TestAllocateAddressEnsuresDefaultVPC(t *testing.T) {
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	gate := &vpcGate{}
	networkv1.RegisterVpcServiceServer(srv, gate)
	networkv1.RegisterAddressServiceServer(srv, gate)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///network",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := networkClient{&api{
		vpcs:      networkv1.NewVpcServiceClient(conn),
		addresses: networkv1.NewAddressServiceClient(conn),
	}}
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	acc, err := client.AllocateAddress(context.Background(), backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: "addr-token", Fingerprint: "fp",
	}, resource.AllocateAddressRequest{Domain: "vpc"})
	if err != nil || acc.Items[0].ID.IsZero() || acc.Items[0].Domain != "vpc" {
		t.Fatalf("%v %+v", err, acc.Items)
	}
	gate.mu.Lock()
	cidr := gate.cidr
	gate.mu.Unlock()
	if cidr != defaultVPCCIDR {
		t.Fatalf("cidr %s", cidr)
	}
}

// vpcList serves a fixed ListVpcs answer, two per page, in the order given.
type vpcList struct {
	networkv1.UnimplementedVpcServiceServer
	vpcs []*networkv1.Vpc
}

func (s *vpcList) ListVpcs(_ context.Context, req *networkv1.ListVpcsRequest) (*networkv1.ListVpcsResponse, error) {
	start := 0
	if req.GetPageToken() != "" {
		start, _ = strconv.Atoi(req.GetPageToken())
	}
	end := min(start+2, len(s.vpcs))
	next := ""
	if end < len(s.vpcs) {
		next = strconv.Itoa(end)
	}
	return &networkv1.ListVpcsResponse{Vpcs: s.vpcs[start:end], NextPageToken: next}, nil
}

func TestEnsureVPCIgnoresListOrder(t *testing.T) {
	at := func(sec int64) *timestamppb.Timestamp { return &timestamppb.Timestamp{Seconds: sec} }
	name := func(id string) string { return "projects/p/regions/" + resource.RegionName + "/vpcs/" + id }
	vpcs := []*networkv1.Vpc{
		{Name: name("vpc-cccccccc"), CreateTime: at(300)},
		{Name: name("vpc-bbbbbbbb"), CreateTime: at(100)},
		{Name: name("vpc-aaaaaaaa"), CreateTime: at(100)},
		{Name: name("vpc-dddddddd"), CreateTime: at(50)},
		{Name: name("vpc-eeeeeeee"), CreateTime: at(200)},
	}
	want := name("vpc-dddddddd")
	// The oldest is on the second page. Ties break by name.
	for i, order := range [][]int{{0, 1, 2, 3, 4}, {4, 3, 2, 1, 0}, {2, 0, 4, 1, 3}} {
		list := make([]*networkv1.Vpc, 0, len(vpcs))
		for _, j := range order {
			list = append(list, vpcs[j])
		}
		if got := ensureOver(t, list); got != want {
			t.Fatalf("order %d: got %s, want %s", i, got, want)
		}
	}
	tied := []*networkv1.Vpc{vpcs[1], vpcs[2]}
	if got := ensureOver(t, tied); got != name("vpc-aaaaaaaa") {
		t.Fatalf("tie: got %s", got)
	}
}

func ensureOver(t *testing.T, vpcs []*networkv1.Vpc) string {
	t.Helper()
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	networkv1.RegisterVpcServiceServer(srv, &vpcList{vpcs: vpcs})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///network",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := networkClient{&api{vpcs: networkv1.NewVpcServiceClient(conn)}}
	got, err := client.ensureVPC(context.Background(), "p")
	if err != nil {
		t.Fatal(err)
	}
	return got
}
