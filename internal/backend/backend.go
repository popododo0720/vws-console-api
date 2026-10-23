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
	"fmt"
	"io"
	"time"

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
	// MintedToken is set when the service minted the client token because
	// the caller sent none. No caller can send that token again, so a
	// backend need not remember the request beyond its own idempotency
	// record. DetachVolume uses it to skip its replay record (#303).
	MintedToken bool
}

// ClientTokenWindow is how long a client token is remembered: a retry with
// the same token and parameters within it returns the original result. It
// is the vws-compute request_id window (vws-proto operation.proto, "A
// request_id is remembered for 24 hours"), so a record console-api keeps
// for a retry, such as a DetachVolume record, never outlives the request id
// compute would replay. This is the one definition; #305 states and tests
// what a retry after the window answers.
const ClientTokenWindow = 24 * time.Hour

// ClientTokenGrace is how much longer than ClientTokenWindow a record is
// kept. A record's stamp is read from the clock before the compute call that
// starts compute's window, so the record outlives the request id by at most
// this, never the other way round (PR #316 review).
const ClientTokenGrace = time.Minute

// ClientTokenExpired reports whether a record stamped at is no longer
// needed at now: more than ClientTokenWindow and ClientTokenGrace have
// passed. A stamp ahead of now is clock skew and has not expired.
func ClientTokenExpired(at, now time.Time) bool {
	return now.Sub(at) > ClientTokenWindow+ClientTokenGrace
}

// MaxDetachReplays is how many DetachVolume requests with a client token
// one instance remembers within ClientTokenWindow. Each takes two of the
// instance's 64 labels, so with resource.MaxTags user tags the records
// always fit. One more within the window is CodeResourceExhausted; a detach
// without a client token is not limited (#303).
const MaxDetachReplays = 4

// DetachReplaysExhausted is the error for a DetachVolume request with a
// client token on an instance that already remembers MaxDetachReplays
// detaches within ClientTokenWindow. Nothing has changed when it is
// returned, so the caller may retry later or detach without a client token.
func DetachReplaysExhausted(id resource.InstanceID) error {
	return &resource.Error{Code: resource.CodeResourceExhausted, Message: fmt.Sprintf(
		"instance %s already has %d detaches with a client token in the last %d hours; "+
			"retry later, or detach without a client token",
		id, MaxDetachReplays, int(ClientTokenWindow.Hours()))}
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
	StartInstances(ctx context.Context, m Mutation, req resource.StartInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error)
	TerminateInstances(ctx context.Context, m Mutation, req resource.TerminateInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error)
	DescribeInstances(ctx context.Context, s Scope, q resource.InstanceQuery) (resource.Page[resource.Instance], error)
	CreateTags(ctx context.Context, m Mutation, req resource.CreateTagsRequest) (resource.Accepted[resource.Instance], error)
	CreateVolume(ctx context.Context, m Mutation, req resource.CreateVolumeRequest) (resource.Accepted[resource.Volume], error)
	AttachVolume(ctx context.Context, m Mutation, req resource.AttachVolumeRequest) (resource.Accepted[resource.Volume], error)
	DetachVolume(
		ctx context.Context, m Mutation, req resource.DetachVolumeRequest,
	) (resource.Accepted[resource.VolumeAttachment], error)
	DeleteVolume(ctx context.Context, m Mutation, req resource.DeleteVolumeRequest) (resource.Accepted[resource.Volume], error)
	ModifyVolume(ctx context.Context, m Mutation, req resource.ModifyVolumeRequest) (resource.Accepted[resource.Volume], error)
	DescribeVolumes(ctx context.Context, s Scope, q resource.VolumeQuery) (resource.Page[resource.Volume], error)
	DescribeImages(ctx context.Context, s Scope, q resource.ImageQuery) (resource.Page[resource.Image], error)
	CreateKeyPair(ctx context.Context, m Mutation, req resource.CreateKeyPairRequest) (resource.Accepted[resource.KeyPair], error)
	DeleteKeyPair(ctx context.Context, m Mutation, req resource.DeleteKeyPairRequest) (resource.Accepted[resource.KeyPair], error)
	DescribeKeyPairs(ctx context.Context, s Scope, q resource.KeyPairQuery) (resource.Page[resource.KeyPair], error)
	CreateSnapshot(ctx context.Context, m Mutation, req resource.CreateSnapshotRequest) (resource.Accepted[resource.Snapshot], error)
	DeleteSnapshot(ctx context.Context, m Mutation, req resource.DeleteSnapshotRequest) (resource.Accepted[resource.Snapshot], error)
	DescribeSnapshots(ctx context.Context, s Scope, q resource.SnapshotQuery) (resource.Page[resource.Snapshot], error)
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
	// ListObjects returns one page of keys. Prefix and delimiter grouping
	// match resource.PageObjects, including common prefixes.
	ListObjects(ctx context.Context, s Scope, q resource.ObjectQuery) (resource.ObjectListing, error)
}

// Network is the internal network service.
type Network interface {
	Operations
	CreateSubnet(ctx context.Context, m Mutation, req resource.CreateSubnetRequest) (resource.Accepted[resource.Subnet], error)
	DescribeSubnets(ctx context.Context, s Scope, q resource.SubnetQuery) (resource.Page[resource.Subnet], error)
	CreateVpc(ctx context.Context, m Mutation, req resource.CreateVpcRequest) (resource.Accepted[resource.Vpc], error)
	DeleteVpc(ctx context.Context, m Mutation, req resource.DeleteVpcRequest) (resource.Accepted[resource.Vpc], error)
	DescribeVpcs(ctx context.Context, s Scope, q resource.VpcQuery) (resource.Page[resource.Vpc], error)
	TagVpcs(ctx context.Context, m Mutation, req resource.TagVpcsRequest) (resource.Accepted[resource.Vpc], error)
	TagSubnets(ctx context.Context, m Mutation, req resource.TagSubnetsRequest) (resource.Accepted[resource.Subnet], error)
	CreateSecurityGroup(ctx context.Context, m Mutation, req resource.CreateSecurityGroupRequest) (resource.Accepted[resource.SecurityGroup], error)
	DeleteSecurityGroup(ctx context.Context, m Mutation, req resource.DeleteSecurityGroupRequest) (resource.Accepted[resource.SecurityGroup], error)
	DescribeSecurityGroups(ctx context.Context, s Scope, q resource.SecurityGroupQuery) (resource.Page[resource.SecurityGroup], error)
	AuthorizeSecurityGroupIngress(ctx context.Context, m Mutation, req resource.AuthorizeSecurityGroupIngressRequest) (resource.Accepted[resource.SecurityGroup], error)
	DeleteSubnet(ctx context.Context, m Mutation, req resource.DeleteSubnetRequest) (resource.Accepted[resource.Subnet], error)
	AllocateAddress(ctx context.Context, m Mutation, req resource.AllocateAddressRequest) (resource.Accepted[resource.Address], error)
	ReleaseAddress(ctx context.Context, m Mutation, req resource.ReleaseAddressRequest) (resource.Accepted[resource.Address], error)
	DescribeAddresses(ctx context.Context, s Scope, q resource.AddressQuery) (resource.Page[resource.Address], error)
	AssociateAddress(ctx context.Context, m Mutation, req resource.AssociateAddressRequest) (resource.Accepted[resource.Address], error)
	DisassociateAddress(ctx context.Context, m Mutation, req resource.DisassociateAddressRequest) (resource.Accepted[resource.Address], error)
}

// Set is the three services one process talks to.
type Set struct {
	Compute Compute
	Storage Storage
	Network Network
}
