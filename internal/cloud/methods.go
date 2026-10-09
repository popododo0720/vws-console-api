package cloud

import (
	"context"
	"io"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// RunInstances accepts a launch and returns the operation.
func (s *Service) RunInstances(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.RunInstancesRequest) (resource.Accepted[resource.Instance], error) {
	return mutate(ctx, s, c, token, req, s.backends.Compute.RunInstances)
}

// StopInstances accepts a stop and returns the operation.
func (s *Service) StopInstances(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.StopInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	return mutate(ctx, s, c, token, req, s.backends.Compute.StopInstances)
}

// DescribeInstances lists instances the caller owns.
func (s *Service) DescribeInstances(ctx context.Context, c resource.Caller, q resource.InstanceQuery) (resource.Page[resource.Instance], error) {
	return readPage(ctx, c, q, s.backends.Compute.DescribeInstances)
}

// GetComputeOperation reads an operation the compute service owns.
func (s *Service) GetComputeOperation(ctx context.Context, c resource.Caller, id resource.OperationID) (resource.Operation, error) {
	if err := requireCaller(c); err != nil {
		return resource.Operation{}, err
	}
	if id.Service() != resource.ServiceCompute {
		return resource.Operation{}, resource.NotFound(resource.KindOperation, id.String())
	}
	op, err := s.backends.Compute.GetOperation(ctx, scope(c), id)
	if err != nil {
		return resource.Operation{}, err
	}
	if err := guardOperation(c.Account, id, op); err != nil {
		return resource.Operation{}, err
	}
	return op, nil
}

// GetNetworkOperation reads an operation the network service owns.
func (s *Service) GetNetworkOperation(ctx context.Context, c resource.Caller, id resource.OperationID) (resource.Operation, error) {
	if err := requireCaller(c); err != nil {
		return resource.Operation{}, err
	}
	if id.Service() != resource.ServiceNetwork {
		return resource.Operation{}, resource.NotFound(resource.KindOperation, id.String())
	}
	op, err := s.backends.Network.GetOperation(ctx, scope(c), id)
	if err != nil {
		return resource.Operation{}, err
	}
	if err := guardOperation(c.Account, id, op); err != nil {
		return resource.Operation{}, err
	}
	return op, nil
}

// GetOperation routes by the service named in the operation id.
func (s *Service) GetOperation(ctx context.Context, c resource.Caller, id resource.OperationID) (resource.Operation, error) {
	switch id.Service() {
	case resource.ServiceCompute:
		return s.GetComputeOperation(ctx, c, id)
	case resource.ServiceNetwork:
		return s.GetNetworkOperation(ctx, c, id)
	case resource.ServiceStorage, resource.ServiceUnspecified:
		return resource.Operation{}, resource.NotFound(resource.KindOperation, id.String())
	default:
		return resource.Operation{}, resource.NotFound(resource.KindOperation, id.String())
	}
}

// CreateSubnet accepts a subnet and returns the operation.
func (s *Service) CreateSubnet(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.CreateSubnetRequest) (resource.Accepted[resource.Subnet], error) {
	return mutate(ctx, s, c, token, req, s.backends.Network.CreateSubnet)
}

// DescribeSubnets lists subnets the caller owns.
func (s *Service) DescribeSubnets(ctx context.Context, c resource.Caller, q resource.SubnetQuery) (resource.Page[resource.Subnet], error) {
	return readPage(ctx, c, q, s.backends.Network.DescribeSubnets)
}

// CreateBucket creates a bucket, or returns it when the caller already owns the name.
func (s *Service) CreateBucket(ctx context.Context, c resource.Caller, name resource.BucketName) (resource.Bucket, error) {
	return readOne(ctx, c, bucketName{name: name}, func(ctx context.Context, sc backend.Scope, q bucketName) (resource.Bucket, error) {
		return s.backends.Storage.CreateBucket(ctx, sc, q.name)
	})
}

// GetBucket reads one bucket.
func (s *Service) GetBucket(ctx context.Context, c resource.Caller, name resource.BucketName) (resource.Bucket, error) {
	return readOne(ctx, c, bucketName{name: name}, func(ctx context.Context, sc backend.Scope, q bucketName) (resource.Bucket, error) {
		return s.backends.Storage.GetBucket(ctx, sc, q.name)
	})
}

// ListBuckets lists buckets the caller owns.
func (s *Service) ListBuckets(ctx context.Context, c resource.Caller, q resource.BucketQuery) (resource.Page[resource.Bucket], error) {
	return readPage(ctx, c, q, s.backends.Storage.ListBuckets)
}

// DeleteBucket removes an empty bucket.
func (s *Service) DeleteBucket(ctx context.Context, c resource.Caller, name resource.BucketName) error {
	if name.IsZero() {
		return resource.Invalid("name", "required")
	}
	return callScoped(ctx, c, func(ctx context.Context, sc backend.Scope) error {
		return s.backends.Storage.DeleteBucket(ctx, sc, name)
	})
}

// PutObject stores an object. The call finishes before it returns.
func (s *Service) PutObject(ctx context.Context, c resource.Caller, req resource.PutObjectRequest, body io.Reader) (resource.Object, error) {
	return readOne(ctx, c, req, func(ctx context.Context, sc backend.Scope, q resource.PutObjectRequest) (resource.Object, error) {
		return s.backends.Storage.PutObject(ctx, sc, q, body)
	})
}

// GetObject reads an object and its body. The caller closes the body.
func (s *Service) GetObject(ctx context.Context, c resource.Caller, req resource.GetObjectRequest) (resource.Object, io.ReadCloser, error) {
	if err := requireCaller(c); err != nil {
		return resource.Object{}, nil, err
	}
	req, err := req.Normalize()
	if err != nil {
		return resource.Object{}, nil, err
	}
	meta, rc, err := s.backends.Storage.GetObject(ctx, scope(c), req)
	if err != nil {
		return resource.Object{}, nil, err
	}
	if err := guardOwner(c.Account, meta); err != nil {
		_ = rc.Close()
		return resource.Object{}, nil, err
	}
	return meta, rc, nil
}

// DeleteObject removes an object. A missing object is success.
func (s *Service) DeleteObject(ctx context.Context, c resource.Caller, bucket resource.BucketName, key resource.ObjectKey) error {
	if bucket.IsZero() || key.IsZero() {
		return resource.Invalid("key", "required")
	}
	return callScoped(ctx, c, func(ctx context.Context, sc backend.Scope) error {
		return s.backends.Storage.DeleteObject(ctx, sc, bucket, key)
	})
}

type bucketName struct {
	name resource.BucketName
}

func (q bucketName) Normalize() (bucketName, error) {
	if q.name.IsZero() {
		return bucketName{}, resource.Invalid("name", "required")
	}
	return q, nil
}
