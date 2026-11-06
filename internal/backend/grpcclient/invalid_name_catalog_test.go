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

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// invalidCatalogWorld serves one readable key pair, snapshot and address
// beside one record of each whose resource name is not a resource id.
type invalidCatalogWorld struct {
	computev1.UnimplementedKeyPairServiceServer
	storagev1.UnimplementedSnapshotServiceServer
	networkv1.UnimplementedAddressServiceServer
	keys  []*computev1.KeyPair
	snaps []*storagev1.Snapshot
	addrs []*networkv1.Address
}

func (s *invalidCatalogWorld) ListKeyPairs(
	context.Context, *computev1.ListKeyPairsRequest,
) (*computev1.ListKeyPairsResponse, error) {
	return &computev1.ListKeyPairsResponse{KeyPairs: s.keys}, nil
}

func (s *invalidCatalogWorld) ListSnapshots(
	context.Context, *storagev1.ListSnapshotsRequest,
) (*storagev1.ListSnapshotsResponse, error) {
	return &storagev1.ListSnapshotsResponse{Snapshots: s.snaps}, nil
}

func (s *invalidCatalogWorld) ListAddresses(
	context.Context, *networkv1.ListAddressesRequest,
) (*networkv1.ListAddressesResponse, error) {
	return &networkv1.ListAddressesResponse{Addresses: s.addrs}, nil
}

func (s *invalidCatalogWorld) GetSnapshot(
	_ context.Context, req *storagev1.GetSnapshotRequest,
) (*storagev1.Snapshot, error) {
	for _, snap := range s.snaps {
		if lastSegment(snap.GetName()) == lastSegment(req.GetName()) {
			return snap, nil
		}
	}
	return nil, status.Error(codes.NotFound, "missing snapshot")
}

func dialInvalidCatalogWorld(t *testing.T, world *invalidCatalogWorld) (computeClient, networkClient, *bytes.Buffer) {
	t.Helper()
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	computev1.RegisterKeyPairServiceServer(srv, world)
	storagev1.RegisterSnapshotServiceServer(srv, world)
	networkv1.RegisterAddressServiceServer(srv, world)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///catalog",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var logs bytes.Buffer
	a := &api{
		keys:      computev1.NewKeyPairServiceClient(conn),
		snapshots: storagev1.NewSnapshotServiceClient(conn),
		addresses: networkv1.NewAddressServiceClient(conn),
		log:       slog.New(slog.NewTextHandler(&logs, nil)),
	}
	return computeClient{a}, networkClient{a}, &logs
}

func TestInvalidCatalogNameIsSkippedInList(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const goodKeyID = "key-0123456789abcdef0"
	const goodSnapID = "snap-0123456789abcdef0"
	const badSnapID = "snap-0fedcba9876543210"
	const goodAddrID = "eipalloc-0123456789abcdef0"
	const badAddrID = "eipalloc-0fedcba9876543210"
	badKeyName := "projects/" + projectID + "/keyPairs/key-0fedcba9876543210"
	badSnapName := "projects/" + projectID + "/snapshots/" + badSnapID
	badAddrName := "projects/" + projectID + "/addresses/" + badAddrID
	volume := volumeName(projectID, "vol-0123456789abcdef0")
	world := &invalidCatalogWorld{
		keys: []*computev1.KeyPair{
			{Name: keyPairName(projectID, goodKeyID), Labels: map[string]string{"keyname": "good"}},
			{Name: badKeyName, Labels: map[string]string{"keyname": "bad"}},
		},
		snaps: []*storagev1.Snapshot{
			{Name: snapshotName(projectID, goodSnapID), Spec: &storagev1.SnapshotSpec{Volume: volume}},
			{Name: badSnapName, Spec: &storagev1.SnapshotSpec{Volume: volume}},
		},
		addrs: []*networkv1.Address{
			{Name: addressName(projectID, goodAddrID), Status: &networkv1.AddressStatus{Ipv4: "203.0.113.1"}},
			{Name: badAddrName, Status: &networkv1.AddressStatus{Ipv4: "203.0.113.2"}},
		},
	}
	compute, network, logs := dialInvalidCatalogWorld(t, world)
	ctx := context.Background()
	scope := backend.Scope{Account: account}

	keys, err := compute.DescribeKeyPairs(ctx, scope, resource.KeyPairQuery{})
	if err != nil {
		t.Fatalf("DescribeKeyPairs: %v", err)
	}
	if len(keys.Items) != 1 || keys.Items[0].ID.String() != goodKeyID {
		t.Fatalf("key pairs %+v", keys.Items)
	}
	snaps, err := compute.DescribeSnapshots(ctx, scope, resource.SnapshotQuery{})
	if err != nil {
		t.Fatalf("DescribeSnapshots: %v", err)
	}
	if len(snaps.Items) != 1 || snaps.Items[0].ID.String() != goodSnapID {
		t.Fatalf("snapshots %+v", snaps.Items)
	}
	addrs, err := network.DescribeAddresses(ctx, scope, resource.AddressQuery{})
	if err != nil {
		t.Fatalf("DescribeAddresses: %v", err)
	}
	if len(addrs.Items) != 1 || addrs.Items[0].ID.String() != goodAddrID {
		t.Fatalf("addresses %+v", addrs.Items)
	}
	for _, name := range []string{badKeyName, badSnapName, badAddrName} {
		if !strings.Contains(logs.String(), name) {
			t.Fatalf("no log names %s: %s", name, logs.String())
		}
	}

	bad := must(resource.Parse[resource.SnapshotID](badSnapID))
	good := must(resource.Parse[resource.SnapshotID](goodSnapID))
	named := map[string]func() error{
		"key pair read by name": func() error {
			_, err := compute.DescribeKeyPairs(ctx, scope, resource.KeyPairQuery{Names: []string{"bad"}})
			return err
		},
		"key pair delete by name": func() error {
			_, err := compute.DeleteKeyPair(ctx, backend.Mutation{Scope: scope}, resource.DeleteKeyPairRequest{Name: "bad"})
			return err
		},
		"snapshot read by id": func() error {
			_, err := compute.DescribeSnapshots(ctx, scope, resource.SnapshotQuery{IDs: []resource.SnapshotID{bad}})
			return err
		},
		"snapshot read by two ids": func() error {
			_, err := compute.DescribeSnapshots(ctx, scope, resource.SnapshotQuery{IDs: []resource.SnapshotID{good, bad}})
			return err
		},
		"address read by public ip": func() error {
			_, err := network.DescribeAddresses(ctx, scope, resource.AddressQuery{PublicIPs: []string{"203.0.113.2"}})
			return err
		},
	}
	for name, read := range named {
		if err := read(); resource.CodeOf(err) != resource.CodeInternal {
			t.Errorf("%s: %v, want Internal", name, err)
		}
	}
}
