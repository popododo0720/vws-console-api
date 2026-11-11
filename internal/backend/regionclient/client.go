// Package regionclient adapts the region API read transport to backend.Set.
package regionclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Transport is the read protocol implemented by regionapi.Client.
type Transport interface {
	Call(context.Context, string, string, backend.Scope, any, any) error
}

// New returns a read-only backend. The caller owns the transport's lifetime.
func New(transport Transport) (backend.Set, error) {
	if transport == nil {
		return backend.Set{}, resource.Invalid("transport", "region transport is required")
	}
	return backend.Set{Compute: compute{transport}, Storage: storage{transport}, Network: network{transport}}, nil
}

type compute struct{ transport Transport }

type storage struct{ transport Transport }

type network struct{ transport Transport }

func call[T any](
	ctx context.Context, transport Transport, service, method string, scope backend.Scope, req any,
) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var result T
	if err := transport.Call(ctx, service, method, scope, req, &result); err != nil {
		var zero T
		return zero, fmt.Errorf("region %s.%s: %w", service, method, err)
	}
	return result, nil
}

func (c compute) RunInstances(
	ctx context.Context, _ backend.Mutation, _ resource.RunInstancesRequest,
) (resource.Accepted[resource.Instance], error) {
	return resource.Accepted[resource.Instance]{},
		resource.Unsupported("RunInstances", "region API does not serve mutations")
}

func (c compute) StopInstances(
	ctx context.Context, _ backend.Mutation, _ resource.StopInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	return resource.Accepted[resource.InstanceStateChange]{},
		resource.Unsupported("StopInstances", "region API does not serve mutations")
}

func (c compute) StartInstances(
	ctx context.Context, _ backend.Mutation, _ resource.StartInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	return resource.Accepted[resource.InstanceStateChange]{},
		resource.Unsupported("StartInstances", "region API does not serve mutations")
}

func (c compute) TerminateInstances(
	ctx context.Context, _ backend.Mutation, _ resource.TerminateInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	return resource.Accepted[resource.InstanceStateChange]{},
		resource.Unsupported("TerminateInstances", "region API does not serve mutations")
}

func (c compute) DescribeInstances(
	ctx context.Context, s backend.Scope, q resource.InstanceQuery,
) (resource.Page[resource.Instance], error) {
	return call[resource.Page[resource.Instance]](ctx, c.transport, "Compute", "DescribeInstances", s, q)
}

func (c compute) CreateTags(
	ctx context.Context, _ backend.Mutation, _ resource.CreateTagsRequest,
) (resource.Accepted[resource.Instance], error) {
	return resource.Accepted[resource.Instance]{},
		resource.Unsupported("CreateTags", "region API does not serve mutations")
}

func (c compute) DeleteTags(
	ctx context.Context, _ backend.Mutation, _ resource.DeleteTagsRequest,
) (resource.Accepted[resource.Instance], error) {
	return resource.Accepted[resource.Instance]{},
		resource.Unsupported("DeleteTags", "region API does not serve mutations")
}

func (c compute) CreateVolume(
	ctx context.Context, _ backend.Mutation, _ resource.CreateVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	return resource.Accepted[resource.Volume]{},
		resource.Unsupported("CreateVolume", "region API does not serve mutations")
}

func (c compute) TagVolumes(
	ctx context.Context, _ backend.Mutation, _ resource.TagVolumesRequest,
) (resource.Accepted[resource.Volume], error) {
	return resource.Accepted[resource.Volume]{}, resource.Unsupported("TagVolumes", "region API does not serve mutations")
}

func (c compute) AttachVolume(
	ctx context.Context, _ backend.Mutation, _ resource.AttachVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	return resource.Accepted[resource.Volume]{},
		resource.Unsupported("AttachVolume", "region API does not serve mutations")
}

func (c compute) DetachVolume(
	ctx context.Context, _ backend.Mutation, _ resource.DetachVolumeRequest,
) (resource.Accepted[resource.VolumeAttachment], error) {
	return resource.Accepted[resource.VolumeAttachment]{},
		resource.Unsupported("DetachVolume", "region API does not serve mutations")
}

func (c compute) DeleteVolume(
	ctx context.Context, _ backend.Mutation, _ resource.DeleteVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	return resource.Accepted[resource.Volume]{},
		resource.Unsupported("DeleteVolume", "region API does not serve mutations")
}

func (c compute) ModifyVolume(
	ctx context.Context, _ backend.Mutation, _ resource.ModifyVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	return resource.Accepted[resource.Volume]{},
		resource.Unsupported("ModifyVolume", "region API does not serve mutations")
}

func (c compute) DescribeVolumes(
	ctx context.Context, s backend.Scope, q resource.VolumeQuery,
) (resource.Page[resource.Volume], error) {
	return call[resource.Page[resource.Volume]](ctx, c.transport, "Compute", "DescribeVolumes", s, q)
}

func (c compute) DescribeImages(
	ctx context.Context, s backend.Scope, q resource.ImageQuery,
) (resource.Page[resource.Image], error) {
	return call[resource.Page[resource.Image]](ctx, c.transport, "Compute", "DescribeImages", s, q)
}

func (c compute) CreateKeyPair(
	ctx context.Context, _ backend.Mutation, _ resource.CreateKeyPairRequest,
) (resource.Accepted[resource.KeyPair], error) {
	return resource.Accepted[resource.KeyPair]{},
		resource.Unsupported("CreateKeyPair", "region API does not serve mutations")
}

func (c compute) DeleteKeyPair(
	ctx context.Context, _ backend.Mutation, _ resource.DeleteKeyPairRequest,
) (resource.Accepted[resource.KeyPair], error) {
	return resource.Accepted[resource.KeyPair]{},
		resource.Unsupported("DeleteKeyPair", "region API does not serve mutations")
}

func (c compute) DescribeKeyPairs(
	ctx context.Context, s backend.Scope, q resource.KeyPairQuery,
) (resource.Page[resource.KeyPair], error) {
	return call[resource.Page[resource.KeyPair]](ctx, c.transport, "Compute", "DescribeKeyPairs", s, q)
}

func (c compute) CreateSnapshot(
	ctx context.Context, _ backend.Mutation, _ resource.CreateSnapshotRequest,
) (resource.Accepted[resource.Snapshot], error) {
	return resource.Accepted[resource.Snapshot]{},
		resource.Unsupported("CreateSnapshot", "region API does not serve mutations")
}

func (c compute) DeleteSnapshot(
	ctx context.Context, _ backend.Mutation, _ resource.DeleteSnapshotRequest,
) (resource.Accepted[resource.Snapshot], error) {
	return resource.Accepted[resource.Snapshot]{},
		resource.Unsupported("DeleteSnapshot", "region API does not serve mutations")
}

func (c compute) DescribeSnapshots(
	ctx context.Context, s backend.Scope, q resource.SnapshotQuery,
) (resource.Page[resource.Snapshot], error) {
	return call[resource.Page[resource.Snapshot]](ctx, c.transport, "Compute", "DescribeSnapshots", s, q)
}

func (c compute) RegisterImage(
	ctx context.Context, _ backend.Mutation, _ resource.RegisterImageRequest,
) (resource.Accepted[resource.Image], error) {
	return resource.Accepted[resource.Image]{},
		resource.Unsupported("RegisterImage", "region API does not serve mutations")
}

func (c compute) GetOperation(
	ctx context.Context, s backend.Scope, id resource.OperationID,
) (resource.Operation, error) {
	return call[resource.Operation](ctx, c.transport, "Compute", "GetOperation", s, id)
}

func (c storage) CreateBucket(ctx context.Context, _ backend.Scope, _ resource.BucketName) (resource.Bucket, error) {
	return resource.Bucket{}, resource.Unsupported("CreateBucket", "region API does not serve mutations")
}

func (c storage) GetBucket(ctx context.Context, s backend.Scope, name resource.BucketName) (resource.Bucket, error) {
	return call[resource.Bucket](ctx, c.transport, "Storage", "GetBucket", s, name)
}

func (c storage) ListBuckets(
	ctx context.Context, s backend.Scope, q resource.BucketQuery,
) (resource.Page[resource.Bucket], error) {
	return call[resource.Page[resource.Bucket]](ctx, c.transport, "Storage", "ListBuckets", s, q)
}

func (c storage) DeleteBucket(ctx context.Context, _ backend.Scope, _ resource.BucketName) error {
	return resource.Unsupported("DeleteBucket", "region API does not serve mutations")
}

func (c storage) PutObject(
	ctx context.Context, _ backend.Scope, _ resource.PutObjectRequest, _ io.Reader,
) (resource.Object, error) {
	return resource.Object{}, resource.Unsupported("PutObject", "region API does not serve mutations")
}

func (c storage) GetObject(
	ctx context.Context, s backend.Scope, req resource.GetObjectRequest,
) (resource.Object, io.ReadCloser, error) {
	result, err := call[struct {
		Object resource.Object `json:"object"`
		Body   []byte          `json:"body"`
	}](ctx, c.transport, "Storage", "GetObject", s, req)
	if err != nil {
		return resource.Object{}, nil, err
	}
	return result.Object, io.NopCloser(bytes.NewReader(result.Body)), nil
}

func (c storage) DeleteObject(ctx context.Context, _ backend.Scope, _ resource.BucketName, _ resource.ObjectKey) error {
	return resource.Unsupported("DeleteObject", "region API does not serve mutations")
}

func (c storage) ListObjects(
	ctx context.Context, s backend.Scope, q resource.ObjectQuery,
) (resource.ObjectListing, error) {
	return call[resource.ObjectListing](ctx, c.transport, "Storage", "ListObjects", s, q)
}

func (c network) CreateSubnet(
	ctx context.Context, _ backend.Mutation, _ resource.CreateSubnetRequest,
) (resource.Accepted[resource.Subnet], error) {
	return resource.Accepted[resource.Subnet]{},
		resource.Unsupported("CreateSubnet", "region API does not serve mutations")
}

func (c network) DescribeSubnets(
	ctx context.Context, s backend.Scope, q resource.SubnetQuery,
) (resource.Page[resource.Subnet], error) {
	return call[resource.Page[resource.Subnet]](ctx, c.transport, "Network", "DescribeSubnets", s, q)
}

func (c network) CreateVpc(
	ctx context.Context, _ backend.Mutation, _ resource.CreateVpcRequest,
) (resource.Accepted[resource.Vpc], error) {
	return resource.Accepted[resource.Vpc]{}, resource.Unsupported("CreateVpc", "region API does not serve mutations")
}

func (c network) DeleteVpc(
	ctx context.Context, _ backend.Mutation, _ resource.DeleteVpcRequest,
) (resource.Accepted[resource.Vpc], error) {
	return resource.Accepted[resource.Vpc]{}, resource.Unsupported("DeleteVpc", "region API does not serve mutations")
}

func (c network) DescribeVpcs(
	ctx context.Context, s backend.Scope, q resource.VpcQuery,
) (resource.Page[resource.Vpc], error) {
	return call[resource.Page[resource.Vpc]](ctx, c.transport, "Network", "DescribeVpcs", s, q)
}

func (c network) TagVpcs(
	ctx context.Context, _ backend.Mutation, _ resource.TagVpcsRequest,
) (resource.Accepted[resource.Vpc], error) {
	return resource.Accepted[resource.Vpc]{}, resource.Unsupported("TagVpcs", "region API does not serve mutations")
}

func (c network) TagSubnets(
	ctx context.Context, _ backend.Mutation, _ resource.TagSubnetsRequest,
) (resource.Accepted[resource.Subnet], error) {
	return resource.Accepted[resource.Subnet]{}, resource.Unsupported("TagSubnets", "region API does not serve mutations")
}

func (c network) UntagVpcs(
	ctx context.Context, _ backend.Mutation, _ resource.UntagVpcsRequest,
) (resource.Accepted[resource.Vpc], error) {
	return resource.Accepted[resource.Vpc]{}, resource.Unsupported("UntagVpcs", "region API does not serve mutations")
}

func (c network) UntagSubnets(
	ctx context.Context, _ backend.Mutation, _ resource.UntagSubnetsRequest,
) (resource.Accepted[resource.Subnet], error) {
	return resource.Accepted[resource.Subnet]{},
		resource.Unsupported("UntagSubnets", "region API does not serve mutations")
}

func (c network) CreateSecurityGroup(
	ctx context.Context, _ backend.Mutation, _ resource.CreateSecurityGroupRequest,
) (resource.Accepted[resource.SecurityGroup], error) {
	return resource.Accepted[resource.SecurityGroup]{},
		resource.Unsupported("CreateSecurityGroup", "region API does not serve mutations")
}

func (c network) DeleteSecurityGroup(
	ctx context.Context, _ backend.Mutation, _ resource.DeleteSecurityGroupRequest,
) (resource.Accepted[resource.SecurityGroup], error) {
	return resource.Accepted[resource.SecurityGroup]{},
		resource.Unsupported("DeleteSecurityGroup", "region API does not serve mutations")
}

func (c network) DescribeSecurityGroups(
	ctx context.Context, s backend.Scope, q resource.SecurityGroupQuery,
) (resource.Page[resource.SecurityGroup], error) {
	return call[resource.Page[resource.SecurityGroup]](ctx, c.transport, "Network", "DescribeSecurityGroups", s, q)
}

func (c network) AuthorizeSecurityGroupIngress(
	ctx context.Context, _ backend.Mutation, _ resource.AuthorizeSecurityGroupIngressRequest,
) (resource.Accepted[resource.SecurityGroup], error) {
	return resource.Accepted[resource.SecurityGroup]{},
		resource.Unsupported("AuthorizeSecurityGroupIngress", "region API does not serve mutations")
}

func (c network) RevokeSecurityGroupIngress(
	ctx context.Context, _ backend.Mutation, _ resource.RevokeSecurityGroupIngressRequest,
) (resource.Accepted[resource.SecurityGroup], error) {
	return resource.Accepted[resource.SecurityGroup]{},
		resource.Unsupported("RevokeSecurityGroupIngress", "region API does not serve mutations")
}

func (c network) DeleteSubnet(
	ctx context.Context, _ backend.Mutation, _ resource.DeleteSubnetRequest,
) (resource.Accepted[resource.Subnet], error) {
	return resource.Accepted[resource.Subnet]{},
		resource.Unsupported("DeleteSubnet", "region API does not serve mutations")
}

func (c network) AllocateAddress(
	ctx context.Context, _ backend.Mutation, _ resource.AllocateAddressRequest,
) (resource.Accepted[resource.Address], error) {
	return resource.Accepted[resource.Address]{},
		resource.Unsupported("AllocateAddress", "region API does not serve mutations")
}

func (c network) ReleaseAddress(
	ctx context.Context, _ backend.Mutation, _ resource.ReleaseAddressRequest,
) (resource.Accepted[resource.Address], error) {
	return resource.Accepted[resource.Address]{},
		resource.Unsupported("ReleaseAddress", "region API does not serve mutations")
}

func (c network) DescribeAddresses(
	ctx context.Context, s backend.Scope, q resource.AddressQuery,
) (resource.Page[resource.Address], error) {
	return call[resource.Page[resource.Address]](ctx, c.transport, "Network", "DescribeAddresses", s, q)
}

func (c network) AssociateAddress(
	ctx context.Context, _ backend.Mutation, _ resource.AssociateAddressRequest,
) (resource.Accepted[resource.Address], error) {
	return resource.Accepted[resource.Address]{},
		resource.Unsupported("AssociateAddress", "region API does not serve mutations")
}

func (c network) DisassociateAddress(
	ctx context.Context, _ backend.Mutation, _ resource.DisassociateAddressRequest,
) (resource.Accepted[resource.Address], error) {
	return resource.Accepted[resource.Address]{},
		resource.Unsupported("DisassociateAddress", "region API does not serve mutations")
}

func (c network) GetOperation(
	ctx context.Context, s backend.Scope, id resource.OperationID,
) (resource.Operation, error) {
	return call[resource.Operation](ctx, c.transport, "Network", "GetOperation", s, id)
}
