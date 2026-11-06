package grpcclient

import (
	"context"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// networkStateWorld serves VPCs and their subnets as stored.
type networkStateWorld struct {
	networkv1.UnimplementedVpcServiceServer
	networkv1.UnimplementedSubnetServiceServer
	vpcs    []*networkv1.Vpc
	subnets []*networkv1.Subnet
}

func (s *networkStateWorld) ListVpcs(context.Context, *networkv1.ListVpcsRequest) (*networkv1.ListVpcsResponse, error) {
	return &networkv1.ListVpcsResponse{Vpcs: s.vpcs}, nil
}

func (s *networkStateWorld) GetVpc(_ context.Context, req *networkv1.GetVpcRequest) (*networkv1.Vpc, error) {
	for _, vpc := range s.vpcs {
		if vpc.GetName() == req.GetName() {
			return vpc, nil
		}
	}
	return nil, status.Error(codes.NotFound, "missing vpc")
}

func (s *networkStateWorld) ListSubnets(
	_ context.Context, req *networkv1.ListSubnetsRequest,
) (*networkv1.ListSubnetsResponse, error) {
	var out []*networkv1.Subnet
	for _, sub := range s.subnets {
		if strings.HasPrefix(sub.GetName(), req.GetParent()+"/") {
			out = append(out, sub)
		}
	}
	return &networkv1.ListSubnetsResponse{Subnets: out}, nil
}

func dialNetworkStateWorld(t *testing.T, world *networkStateWorld) networkClient {
	t.Helper()
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	networkv1.RegisterVpcServiceServer(srv, world)
	networkv1.RegisterSubnetServiceServer(srv, world)
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
	return networkClient{&api{
		vpcs:    networkv1.NewVpcServiceClient(conn),
		subnets: networkv1.NewSubnetServiceClient(conn),
	}}
}

func observedVpc(projectID, id string, state commonv1.ReconciliationState) *networkv1.Vpc {
	return &networkv1.Vpc{
		Name:   vpcName(projectID, id),
		Spec:   &networkv1.VpcSpec{Ipv4Cidr: "10.0.0.0/16"},
		Status: &networkv1.VpcStatus{Observed: &commonv1.ObservedState{State: state}},
	}
}

func observedSubnet(projectID, vpcID, id string, state commonv1.ReconciliationState) *networkv1.Subnet {
	return &networkv1.Subnet{
		Name:   subnetName(projectID, vpcID, id),
		Spec:   &networkv1.SubnetSpec{Zone: resource.ZoneName, Ipv4Cidr: "10.0.1.0/24"},
		Status: &networkv1.SubnetStatus{Observed: &commonv1.ObservedState{State: state}},
	}
}

// TestFailedNetworkRecordDoesNotFailDescribe pins #231: a VPC or subnet in a
// reconciliation ERROR, UNSPECIFIED or unknown state is listed beside healthy
// ones. EC2 documents subnet state failed, so such a subnet is failed. EC2
// documents only pending and available for a VPC, so such a VPC is pending.
func TestFailedNetworkRecordDoesNotFailDescribe(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const healthyVpc = "vpc-01234567"
	const brokenVpc = "vpc-0fedcba9"
	const healthySubnet = "subnet-01234567"
	const brokenSubnet = "subnet-0fedcba9"
	ready := commonv1.ReconciliationState_RECONCILIATION_STATE_READY
	for _, state := range []commonv1.ReconciliationState{
		commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR,
		commonv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED,
		99,
	} {
		world := &networkStateWorld{
			vpcs: []*networkv1.Vpc{
				observedVpc(projectID, healthyVpc, ready),
				observedVpc(projectID, brokenVpc, state),
			},
			subnets: []*networkv1.Subnet{
				observedSubnet(projectID, healthyVpc, healthySubnet, ready),
				observedSubnet(projectID, healthyVpc, brokenSubnet, state),
			},
		}
		client := dialNetworkStateWorld(t, world)
		ctx := context.Background()
		scope := backend.Scope{Account: account}

		vpcs, err := client.DescribeVpcs(ctx, scope, resource.VpcQuery{})
		if err != nil {
			t.Fatalf("state %d: DescribeVpcs: %v", state, err)
		}
		vpcByID := map[string]string{}
		for _, vpc := range vpcs.Items {
			vpcByID[vpc.ID.String()] = vpc.State
		}
		if len(vpcs.Items) != 2 || vpcByID[healthyVpc] != resource.VpcAvailable || vpcByID[brokenVpc] != resource.VpcPending {
			t.Fatalf("state %d: vpcs %+v", state, vpcs.Items)
		}
		vid, err := resource.Parse[resource.VpcID](brokenVpc)
		if err != nil {
			t.Fatal(err)
		}
		one, err := client.DescribeVpcs(ctx, scope, resource.VpcQuery{IDs: []resource.VpcID{vid}})
		if err != nil || len(one.Items) != 1 || one.Items[0].State != resource.VpcPending {
			t.Fatalf("state %d: describe one vpc: %v %+v", state, err, one.Items)
		}

		subnets, err := client.DescribeSubnets(ctx, scope, resource.SubnetQuery{})
		if err != nil {
			t.Fatalf("state %d: DescribeSubnets: %v", state, err)
		}
		subByID := map[string]resource.SubnetState{}
		for _, sub := range subnets.Items {
			subByID[sub.ID.String()] = sub.State
		}
		if len(subnets.Items) != 2 || subByID[healthySubnet] != resource.SubnetAvailable ||
			subByID[brokenSubnet] != resource.SubnetFailed {
			t.Fatalf("state %d: subnets %+v", state, subnets.Items)
		}
		sid, err := resource.Parse[resource.SubnetID](brokenSubnet)
		if err != nil {
			t.Fatal(err)
		}
		named, err := client.DescribeSubnets(ctx, scope, resource.SubnetQuery{IDs: []resource.SubnetID{sid}})
		if err != nil || len(named.Items) != 1 || named.Items[0].State != resource.SubnetFailed {
			t.Fatalf("state %d: describe one subnet: %v %+v", state, err, named.Items)
		}
	}
}

func TestSubnetFailedRoundTrip(t *testing.T) {
	text, err := resource.SubnetFailed.MarshalText()
	if err != nil || string(text) != "failed" {
		t.Fatalf("marshal %q %v", text, err)
	}
	var back resource.SubnetState
	if err := back.UnmarshalText(text); err != nil || back != resource.SubnetFailed {
		t.Fatalf("unmarshal %s %v", back, err)
	}
	wire := subnetProto(resource.Subnet{ID: mustSubnet(t), State: resource.SubnetFailed}, "p", "vpc-01234567")
	if wire.GetStatus().GetObserved().GetState() != commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR {
		t.Fatalf("proto %s", wire.GetStatus().GetObserved().GetState())
	}
}
