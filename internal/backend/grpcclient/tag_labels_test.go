package grpcclient

import (
	"bytes"
	"context"
	"log/slog"
	"maps"
	"net"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

var labelKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

// awsTags are valid EC2 tags that compute labels cannot hold as they are.
func awsTags() map[string]string {
	return map[string]string{
		"Name":                    "web-1",
		"env":                     "dev",
		"Owner Team":              "Platform / SRE: a=b, c+d @x",
		"vws-looks-internal":      "user value",
		"aws:cloudformation:name": "stack",
		"lower_but_long_value":    strings.Repeat("v", 256),
		strings.Repeat("K", 128):  "max key",
		"유니코드":                    strings.Repeat("값", 85), // 255 bytes
		"empty":                   "",
	}
}

func checkLabels(t *testing.T, labels map[string]string) {
	t.Helper()
	if len(labels) > 64 {
		t.Fatalf("%d labels, compute takes 64", len(labels))
	}
	for k, v := range labels {
		if !labelKeyRE.MatchString(k) {
			t.Fatalf("label key %q breaks the compute grammar", k)
		}
		if len(v) > 63 || !utf8.ValidString(v) || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			t.Fatalf("label %s value %q breaks the compute grammar", k, v)
		}
	}
}

func TestTagsRoundTripThroughLabels(t *testing.T) {
	tags := awsTags()
	labels, err := withInternalLabels(tags, map[string]string{labelImage: "ami-0123456789abcdef0"})
	if err != nil {
		t.Fatal(err)
	}
	checkLabels(t, labels)
	if got, err := userTags(labels); err != nil || !maps.Equal(got, tags) {
		t.Fatalf("round trip\n got %q\nwant %q", got, tags)
	}
	if labels["env"] != "dev" {
		t.Fatalf("a tag that is a valid label stays a plain label for filtering: %v", labels)
	}
}

func TestLegacyNameLabelStillReads(t *testing.T) {
	if got, err := userTags(map[string]string{labelNameTag: "old"}); err != nil || got["Name"] != "old" {
		t.Fatalf("%v", got)
	}
}

func TestTagsOverLabelCapacityFail(t *testing.T) {
	tags := map[string]string{}
	for i := 0; i < 20; i++ {
		tags[strings.Repeat("K", 127)+string(rune('a'+i))] = strings.Repeat("v", 256)
	}
	if _, err := withInternalLabels(tags, nil); err == nil {
		t.Fatal("20 maximal tags cannot fit in 64 labels of 63 bytes; want an error, not silent loss")
	}
}

func TestUndecodableTagChunksFail(t *testing.T) {
	labels, err := withInternalLabels(awsTags(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, missing := range []int{0, 1} {
		broken := maps.Clone(labels)
		delete(broken, tagChunkKey(missing))
		if got, err := userTags(broken); resource.CodeOf(err) != resource.CodeInternal {
			t.Fatalf("missing tag chunk %d read as %q, %v; want Internal, not tags without the packed ones", missing, got, err)
		}
		_, _, err := mergedLabels(broken, map[string]string{"env": "prod"})
		if resource.CodeOf(err) != resource.CodeInternal {
			t.Fatalf("CreateTags over missing chunk %d: %v; want Internal, not a rewrite that drops them", missing, err)
		}
	}
}

func TestUndecodableTagChunksAreSkippedInList(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const goodID, badID = "i-0123456789abcdef0", "i-0fedcba9876543210"
	bad := observedInstance(projectID, badID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY, computev1.InstancePower_INSTANCE_POWER_RUNNING)
	maps.Copy(bad.Labels, map[string]string{tagChunkKey(0): `{"Owner Team":`})
	client, logs := dialInvalidNameWorld(t, &invalidNameWorld{inst: []*computev1.Instance{
		observedInstance(projectID, goodID,
			commonv1.ReconciliationState_RECONCILIATION_STATE_READY, computev1.InstancePower_INSTANCE_POWER_RUNNING),
		bad,
	}})
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	page, err := client.DescribeInstances(ctx, scope, resource.InstanceQuery{})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID.String() != goodID {
		t.Fatalf("listing %+v, %v; want only %s", page.Items, err, goodID)
	}
	if !strings.Contains(logs.String(), "id="+badID) || strings.Contains(logs.String(), account.String()) {
		t.Fatalf("the skipped record is not logged by id alone: %s", logs.String())
	}
	id, err := resource.Parse[resource.InstanceID](badID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DescribeInstances(ctx, scope, resource.InstanceQuery{IDs: []resource.InstanceID{id}})
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("an id read of the bad record: %v; want Internal", err)
	}
}

// badTagNetwork serves VPCs and subnets, some with tag chunks that do not
// decode.
type badTagNetwork struct {
	networkv1.UnimplementedVpcServiceServer
	networkv1.UnimplementedSubnetServiceServer
	vpcs    []*networkv1.Vpc
	subnets []*networkv1.Subnet
}

func (s *badTagNetwork) ListVpcs(context.Context, *networkv1.ListVpcsRequest) (*networkv1.ListVpcsResponse, error) {
	return &networkv1.ListVpcsResponse{Vpcs: s.vpcs}, nil
}

func (s *badTagNetwork) GetVpc(_ context.Context, req *networkv1.GetVpcRequest) (*networkv1.Vpc, error) {
	for _, vpc := range s.vpcs {
		if vpc.GetName() == req.GetName() {
			return vpc, nil
		}
	}
	return nil, status.Error(codes.NotFound, "missing vpc")
}

func (s *badTagNetwork) ListSubnets(
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

func dialBadTagNetwork(t *testing.T, world *badTagNetwork) (networkClient, *bytes.Buffer) {
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
	var logs bytes.Buffer
	return networkClient{&api{
		vpcs:    networkv1.NewVpcServiceClient(conn),
		subnets: networkv1.NewSubnetServiceClient(conn),
		log:     slog.New(slog.NewTextHandler(&logs, nil)),
	}}, &logs
}

func badTagVpc(projectID, id string) *networkv1.Vpc {
	vpc := vpcProto(resource.Vpc{Cidr: "10.0.0.0/16", State: resource.VpcAvailable}, projectID)
	vpc.Name = vpcName(projectID, id)
	return vpc
}

func TestUndecodableSubnetTagChunksAreSkippedInList(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const vpcID, goodID, badID = "vpc-0123456789abcdef0", "subnet-0123456789abcdef0", "subnet-0fedcba9876543210"
	good := subnetProto(resource.Subnet{Cidr: "10.0.1.0/24", State: resource.SubnetAvailable}, projectID, vpcID)
	good.Name = subnetName(projectID, vpcID, goodID)
	bad := subnetProto(resource.Subnet{Cidr: "10.0.2.0/24", State: resource.SubnetAvailable}, projectID, vpcID)
	bad.Name = subnetName(projectID, vpcID, badID)
	bad.Labels = map[string]string{tagChunkKey(0): `{"Owner Team":`}
	client, logs := dialBadTagNetwork(t, &badTagNetwork{
		vpcs:    []*networkv1.Vpc{badTagVpc(projectID, vpcID)},
		subnets: []*networkv1.Subnet{good, bad},
	})
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	page, err := client.DescribeSubnets(ctx, scope, resource.SubnetQuery{})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID.String() != goodID {
		t.Fatalf("listing %+v, %v; want only %s", page.Items, err, goodID)
	}
	if !strings.Contains(logs.String(), "id="+badID) || strings.Contains(logs.String(), account.String()) {
		t.Fatalf("the skipped record is not logged by id alone: %s", logs.String())
	}
	id, err := resource.Parse[resource.SubnetID](badID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DescribeSubnets(ctx, scope, resource.SubnetQuery{IDs: []resource.SubnetID{id}})
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("an id read of the bad record: %v; want Internal", err)
	}
}

func TestUndecodableVpcTagChunksAreSkippedInList(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const goodID, badID = "vpc-0123456789abcdef0", "vpc-0fedcba9876543210"
	bad := badTagVpc(projectID, badID)
	bad.Labels = map[string]string{tagChunkKey(0): `{"Owner Team":`}
	client, logs := dialBadTagNetwork(t, &badTagNetwork{vpcs: []*networkv1.Vpc{badTagVpc(projectID, goodID), bad}})
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	page, err := client.DescribeVpcs(ctx, scope, resource.VpcQuery{})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID.String() != goodID {
		t.Fatalf("listing %+v, %v; want only %s", page.Items, err, goodID)
	}
	if !strings.Contains(logs.String(), "id="+badID) || strings.Contains(logs.String(), account.String()) {
		t.Fatalf("the skipped record is not logged by id alone: %s", logs.String())
	}
	id, err := resource.Parse[resource.VpcID](badID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DescribeVpcs(ctx, scope, resource.VpcQuery{IDs: []resource.VpcID{id}})
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("an id read of the bad record: %v; want Internal", err)
	}
}
