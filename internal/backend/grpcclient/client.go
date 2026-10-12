package grpcclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
)

// Addrs are the internal service endpoints.
type Addrs struct {
	Compute string
	Storage string
	Network string
}

// Client is a backend.Set backed by three gRPC connections.
type Client struct {
	conns []*grpc.ClientConn
	set   backend.Set
}

// Dial opens the three connections. RPC failures surface on the first call.
func Dial(ctx context.Context, addrs Addrs) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	computeConn, err := grpc.NewClient(addrs.Compute, dialOptions()...)
	if err != nil {
		return nil, fmt.Errorf("dial compute: %w", err)
	}
	storageConn, err := grpc.NewClient(addrs.Storage, dialOptions()...)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("dial storage: %w", err), computeConn.Close())
	}
	networkConn, err := grpc.NewClient(addrs.Network, dialOptions()...)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("dial network: %w", err), computeConn.Close(), storageConn.Close())
	}
	shared := &api{
		instances:  computev1.NewInstanceServiceClient(computeConn),
		volumes:    storagev1.NewVolumeServiceClient(storageConn),
		buckets:    storagev1.NewBucketServiceClient(storageConn),
		objects:    storagev1.NewObjectServiceClient(storageConn),
		subnets:    networkv1.NewSubnetServiceClient(networkConn),
		vpcs:       networkv1.NewVpcServiceClient(networkConn),
		groups:     networkv1.NewSecurityGroupServiceClient(networkConn),
		keys:       computev1.NewKeyPairServiceClient(computeConn),
		addresses:  networkv1.NewAddressServiceClient(networkConn),
		snapshots:  storagev1.NewSnapshotServiceClient(storageConn),
		computeOps: longrunningpb.NewOperationsClient(computeConn),
		storageOps: longrunningpb.NewOperationsClient(storageConn),
		networkOps: longrunningpb.NewOperationsClient(networkConn),
	}
	return &Client{
		conns: []*grpc.ClientConn{computeConn, storageConn, networkConn},
		set: backend.Set{
			Compute: computeClient{shared},
			Storage: storageClient{shared},
			Network: networkClient{shared},
		},
	}, nil
}

// MaxMessageBytes is the gRPC frame size. ObjectService promises 8MiB
// responses. It sits above MaxObjectBytes so a full object plus the envelope
// fits in one message.
func MaxMessageBytes() int { return 8 << 20 }

func dialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(MaxMessageBytes()),
			grpc.MaxCallSendMsgSize(MaxMessageBytes()),
		),
		grpc.WithUnaryInterceptor(withDeadline),
	}
}

func withDeadline(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	return invoker(ctx, method, req, reply, cc, opts...)
}

// Set returns the backend contract.
func (c *Client) Set() backend.Set { return c.set }

// Close closes the connections.
func (c *Client) Close() error {
	var err error
	for _, conn := range c.conns {
		if closeErr := conn.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}
