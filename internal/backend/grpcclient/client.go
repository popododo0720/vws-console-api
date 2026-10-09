package grpcclient

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/popododo0720/vws-console-api/internal/backend"
	computev1 "github.com/popododo0720/vws-console-api/internal/backend/grpcclient/internal/pb/computev1"
	networkv1 "github.com/popododo0720/vws-console-api/internal/backend/grpcclient/internal/pb/networkv1"
	storagev1 "github.com/popododo0720/vws-console-api/internal/backend/grpcclient/internal/pb/storagev1"
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
	_ = ctx
	computeConn, err := grpc.NewClient(addrs.Compute, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	storageConn, err := grpc.NewClient(addrs.Storage, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		_ = computeConn.Close()
		return nil, err
	}
	networkConn, err := grpc.NewClient(addrs.Network, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		_ = computeConn.Close()
		_ = storageConn.Close()
		return nil, err
	}
	return &Client{
		conns: []*grpc.ClientConn{computeConn, storageConn, networkConn},
		set: backend.Set{
			Compute: computeClient{computev1.NewComputeClient(computeConn)},
			Storage: storageClient{storagev1.NewStorageClient(storageConn)},
			Network: networkClient{networkv1.NewNetworkClient(networkConn)},
		},
	}, nil
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
