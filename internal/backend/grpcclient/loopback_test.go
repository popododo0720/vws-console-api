package grpcclient

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	commonv1 "github.com/popododo0720/vws-console-api/internal/backend/grpcclient/internal/pb/commonv1"
	computev1 "github.com/popododo0720/vws-console-api/internal/backend/grpcclient/internal/pb/computev1"
	networkv1 "github.com/popododo0720/vws-console-api/internal/backend/grpcclient/internal/pb/networkv1"
	storagev1 "github.com/popododo0720/vws-console-api/internal/backend/grpcclient/internal/pb/storagev1"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestContractOverGRPC(t *testing.T) {
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(MaxMessageBytes()),
		grpc.MaxSendMsgSize(MaxMessageBytes()),
	)
	now := time.Unix(1_700_000_000, 0).UTC()
	world := fake.New(fake.Options{
		Now:     func() time.Time { return now },
		Entropy: &fake.Sequence{},
	})
	set := world.Set()
	computev1.RegisterComputeServer(srv, computeSrv{api: set.Compute})
	storagev1.RegisterStorageServer(srv, storageSrv{api: set.Storage})
	networkv1.RegisterNetworkServer(srv, networkSrv{api: set.Network})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	backendtest.Run(t, func() backend.Set {
		return backend.Set{
			Compute: computeClient{computev1.NewComputeClient(conn)},
			Storage: storageClient{storagev1.NewStorageClient(conn)},
			Network: networkClient{networkv1.NewNetworkClient(conn)},
		}
	})
}

type computeSrv struct {
	computev1.UnimplementedComputeServer
	api backend.Compute
}

func (s computeSrv) RunInstances(ctx context.Context, req *computev1.RunInstancesRequest) (*computev1.InstancesAccepted, error) {
	m, err := mutationModel(req.GetMutation())
	if err != nil {
		return nil, toStatus(err)
	}
	img, err := resource.Parse[resource.ImageID](req.GetImageId())
	if err != nil {
		return nil, toStatus(err)
	}
	sub, err := resource.Parse[resource.SubnetID](req.GetSubnetId())
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.api.RunInstances(ctx, m, resource.RunInstancesRequest{
		ImageID: img, InstanceType: req.GetInstanceType(), SubnetID: sub, Count: int(req.GetCount()), Tags: req.GetTags(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	items := make([]*computev1.Instance, 0, len(acc.Items))
	for _, item := range acc.Items {
		items = append(items, instanceProto(item))
	}
	return &computev1.InstancesAccepted{Operation: operationProto(acc.Operation), Instances: items}, nil
}

func (s computeSrv) StopInstances(ctx context.Context, req *computev1.StopInstancesRequest) (*computev1.StateChangesAccepted, error) {
	m, err := mutationModel(req.GetMutation())
	if err != nil {
		return nil, toStatus(err)
	}
	ids := make([]resource.InstanceID, 0, len(req.GetInstanceIds()))
	for _, raw := range req.GetInstanceIds() {
		id, err := resource.Parse[resource.InstanceID](raw)
		if err != nil {
			return nil, toStatus(err)
		}
		ids = append(ids, id)
	}
	acc, err := s.api.StopInstances(ctx, m, resource.StopInstancesRequest{IDs: ids})
	if err != nil {
		return nil, toStatus(err)
	}
	changes := make([]*computev1.InstanceStateChange, 0, len(acc.Items))
	for _, ch := range acc.Items {
		changes = append(changes, &computev1.InstanceStateChange{
			InstanceId: ch.ID.String(), OwnerId: ch.OwnerID.String(),
			PreviousState: ch.Previous.String(), CurrentState: ch.Current.String(),
		})
	}
	return &computev1.StateChangesAccepted{Operation: operationProto(acc.Operation), Changes: changes}, nil
}

func (s computeSrv) DescribeInstances(ctx context.Context, req *computev1.DescribeInstancesRequest) (*computev1.DescribeInstancesResponse, error) {
	sc, err := scopeModel(req.GetScope())
	if err != nil {
		return nil, toStatus(err)
	}
	var ids []resource.InstanceID
	for _, raw := range req.GetInstanceIds() {
		id, err := resource.Parse[resource.InstanceID](raw)
		if err != nil {
			return nil, toStatus(err)
		}
		ids = append(ids, id)
	}
	var states []resource.InstanceState
	for _, raw := range req.GetStates() {
		st, ok := resource.ParseInstanceState(raw)
		if !ok {
			return nil, toStatus(resource.Invalid("state", "unknown"))
		}
		states = append(states, st)
	}
	page, err := s.api.DescribeInstances(ctx, sc, resource.InstanceQuery{IDs: ids, States: states, Page: pageModel(req.GetPage())})
	if err != nil {
		return nil, toStatus(err)
	}
	items := make([]*computev1.Instance, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, instanceProto(item))
	}
	return &computev1.DescribeInstancesResponse{Instances: items, NextPageToken: page.NextToken}, nil
}

func (s computeSrv) GetOperation(ctx context.Context, req *commonv1.GetOperationRequest) (*commonv1.Operation, error) {
	sc, err := scopeModel(req.GetScope())
	if err != nil {
		return nil, toStatus(err)
	}
	id, err := resource.Parse[resource.OperationID](req.GetOperationId())
	if err != nil {
		return nil, toStatus(err)
	}
	op, err := s.api.GetOperation(ctx, sc, id)
	if err != nil {
		return nil, toStatus(err)
	}
	return operationProto(op), nil
}

type storageSrv struct {
	storagev1.UnimplementedStorageServer
	api backend.Storage
}

func (s storageSrv) CreateBucket(ctx context.Context, req *storagev1.CreateBucketRequest) (*storagev1.Bucket, error) {
	return s.bucket(ctx, req.GetScope(), req.GetName(), s.api.CreateBucket)
}

func (s storageSrv) GetBucket(ctx context.Context, req *storagev1.GetBucketRequest) (*storagev1.Bucket, error) {
	return s.bucket(ctx, req.GetScope(), req.GetName(), s.api.GetBucket)
}

func (s storageSrv) bucket(ctx context.Context, scope *commonv1.Scope, name string, call func(context.Context, backend.Scope, resource.BucketName) (resource.Bucket, error)) (*storagev1.Bucket, error) {
	sc, err := scopeModel(scope)
	if err != nil {
		return nil, toStatus(err)
	}
	parsed, err := resource.Parse[resource.BucketName](name)
	if err != nil {
		return nil, toStatus(err)
	}
	b, err := call(ctx, sc, parsed)
	if err != nil {
		return nil, toStatus(err)
	}
	return bucketProto(b), nil
}

func (s storageSrv) ListBuckets(ctx context.Context, req *storagev1.ListBucketsRequest) (*storagev1.ListBucketsResponse, error) {
	sc, err := scopeModel(req.GetScope())
	if err != nil {
		return nil, toStatus(err)
	}
	page, err := s.api.ListBuckets(ctx, sc, resource.BucketQuery{Page: pageModel(req.GetPage())})
	if err != nil {
		return nil, toStatus(err)
	}
	items := make([]*storagev1.Bucket, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, bucketProto(item))
	}
	return &storagev1.ListBucketsResponse{Buckets: items, NextPageToken: page.NextToken}, nil
}

func (s storageSrv) DeleteBucket(ctx context.Context, req *storagev1.DeleteBucketRequest) (*storagev1.Empty, error) {
	sc, err := scopeModel(req.GetScope())
	if err != nil {
		return nil, toStatus(err)
	}
	name, err := resource.Parse[resource.BucketName](req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.api.DeleteBucket(ctx, sc, name); err != nil {
		return nil, toStatus(err)
	}
	return &storagev1.Empty{}, nil
}

func (s storageSrv) PutObject(ctx context.Context, req *storagev1.PutObjectRequest) (*storagev1.Object, error) {
	sc, err := scopeModel(req.GetScope())
	if err != nil {
		return nil, toStatus(err)
	}
	bucket, err := resource.Parse[resource.BucketName](req.GetBucket())
	if err != nil {
		return nil, toStatus(err)
	}
	key, err := resource.Parse[resource.ObjectKey](req.GetKey())
	if err != nil {
		return nil, toStatus(err)
	}
	obj, err := s.api.PutObject(ctx, sc, resource.PutObjectRequest{
		Bucket: bucket, Key: key, ContentType: req.GetContentType(), Size: req.GetSize(),
	}, bytes.NewReader(req.GetBody()))
	if err != nil {
		return nil, toStatus(err)
	}
	return objectProto(obj), nil
}

func (s storageSrv) GetObject(ctx context.Context, req *storagev1.GetObjectRequest) (*storagev1.GetObjectResponse, error) {
	sc, err := scopeModel(req.GetScope())
	if err != nil {
		return nil, toStatus(err)
	}
	bucket, err := resource.Parse[resource.BucketName](req.GetBucket())
	if err != nil {
		return nil, toStatus(err)
	}
	key, err := resource.Parse[resource.ObjectKey](req.GetKey())
	if err != nil {
		return nil, toStatus(err)
	}
	meta, body, err := s.api.GetObject(ctx, sc, resource.GetObjectRequest{Bucket: bucket, Key: key})
	if err != nil {
		return nil, toStatus(err)
	}
	defer func() { _ = body.Close() }()
	buf, err := io.ReadAll(body)
	if err != nil {
		return nil, toStatus(err)
	}
	return &storagev1.GetObjectResponse{Object: objectProto(meta), Body: buf}, nil
}

func (s storageSrv) DeleteObject(ctx context.Context, req *storagev1.DeleteObjectRequest) (*storagev1.Empty, error) {
	sc, err := scopeModel(req.GetScope())
	if err != nil {
		return nil, toStatus(err)
	}
	bucket, err := resource.Parse[resource.BucketName](req.GetBucket())
	if err != nil {
		return nil, toStatus(err)
	}
	key, err := resource.Parse[resource.ObjectKey](req.GetKey())
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.api.DeleteObject(ctx, sc, bucket, key); err != nil {
		return nil, toStatus(err)
	}
	return &storagev1.Empty{}, nil
}

type networkSrv struct {
	networkv1.UnimplementedNetworkServer
	api backend.Network
}

func (s networkSrv) CreateSubnet(ctx context.Context, req *networkv1.CreateSubnetRequest) (*networkv1.SubnetsAccepted, error) {
	m, err := mutationModel(req.GetMutation())
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.api.CreateSubnet(ctx, m, resource.CreateSubnetRequest{Cidr: req.GetCidrBlock()})
	if err != nil {
		return nil, toStatus(err)
	}
	items := make([]*networkv1.Subnet, 0, len(acc.Items))
	for _, item := range acc.Items {
		items = append(items, subnetProto(item))
	}
	return &networkv1.SubnetsAccepted{Operation: operationProto(acc.Operation), Subnets: items}, nil
}

func (s networkSrv) DescribeSubnets(ctx context.Context, req *networkv1.DescribeSubnetsRequest) (*networkv1.DescribeSubnetsResponse, error) {
	sc, err := scopeModel(req.GetScope())
	if err != nil {
		return nil, toStatus(err)
	}
	var ids []resource.SubnetID
	for _, raw := range req.GetSubnetIds() {
		id, err := resource.Parse[resource.SubnetID](raw)
		if err != nil {
			return nil, toStatus(err)
		}
		ids = append(ids, id)
	}
	page, err := s.api.DescribeSubnets(ctx, sc, resource.SubnetQuery{IDs: ids, Page: pageModel(req.GetPage())})
	if err != nil {
		return nil, toStatus(err)
	}
	items := make([]*networkv1.Subnet, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, subnetProto(item))
	}
	return &networkv1.DescribeSubnetsResponse{Subnets: items, NextPageToken: page.NextToken}, nil
}

func (s networkSrv) GetOperation(ctx context.Context, req *commonv1.GetOperationRequest) (*commonv1.Operation, error) {
	sc, err := scopeModel(req.GetScope())
	if err != nil {
		return nil, toStatus(err)
	}
	id, err := resource.Parse[resource.OperationID](req.GetOperationId())
	if err != nil {
		return nil, toStatus(err)
	}
	op, err := s.api.GetOperation(ctx, sc, id)
	if err != nil {
		return nil, toStatus(err)
	}
	return operationProto(op), nil
}
