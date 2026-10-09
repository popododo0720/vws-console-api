// Package backend is the contract with the internal compute, storage, and
// network services. The interfaces speak resource types, never protobuf.
//
// The backend is the source of truth. This process keeps nothing between calls.
// A method that takes a Mutation returns as soon as the work is accepted.
// Mutation.Key is idempotent: the same key and fingerprint replay the original
// result, including after this process restarts. A different fingerprint with
// the same key is CodeIdempotencyMismatch. Records are kept at least 24 hours.
// Results are scoped to Scope.Account. Another account's resource is
// CodeNotFound. Failures are *resource.Error values.
package backend

import (
	"context"
	"io"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Scope is the tenancy of a call.
type Scope struct {
	Account resource.AccountID
}

// Mutation identifies one client attempt at a long-running change.
// Only package cloud builds a Mutation.
type Mutation struct {
	Scope
	Key         string
	Fingerprint string
}

// Operations reads operations owned by one service.
type Operations interface {
	GetOperation(ctx context.Context, s Scope, id resource.OperationID) (resource.Operation, error)
}

// Compute is the internal compute service.
type Compute interface {
	Operations
	RunInstances(ctx context.Context, m Mutation, req resource.RunInstancesRequest) (resource.Accepted[resource.Instance], error)
	StopInstances(ctx context.Context, m Mutation, req resource.StopInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error)
	DescribeInstances(ctx context.Context, s Scope, q resource.InstanceQuery) (resource.Page[resource.Instance], error)
}

// Storage is the internal storage service. Bucket and object calls finish
// before they return, so they take a Scope rather than a Mutation.
type Storage interface {
	CreateBucket(ctx context.Context, s Scope, name resource.BucketName) (resource.Bucket, error)
	GetBucket(ctx context.Context, s Scope, name resource.BucketName) (resource.Bucket, error)
	ListBuckets(ctx context.Context, s Scope, q resource.BucketQuery) (resource.Page[resource.Bucket], error)
	DeleteBucket(ctx context.Context, s Scope, name resource.BucketName) error
	PutObject(ctx context.Context, s Scope, req resource.PutObjectRequest, body io.Reader) (resource.Object, error)
	GetObject(ctx context.Context, s Scope, req resource.GetObjectRequest) (resource.Object, io.ReadCloser, error)
	DeleteObject(ctx context.Context, s Scope, bucket resource.BucketName, key resource.ObjectKey) error
}

// Network is the internal network service.
type Network interface {
	Operations
	CreateSubnet(ctx context.Context, m Mutation, req resource.CreateSubnetRequest) (resource.Accepted[resource.Subnet], error)
	DescribeSubnets(ctx context.Context, s Scope, q resource.SubnetQuery) (resource.Page[resource.Subnet], error)
}

// Set is the three services one process talks to.
type Set struct {
	Compute Compute
	Storage Storage
	Network Network
}
