// Package regionclient adapts the region API transport to backend.Set.
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

// Transport is the protocol implemented by regionapi.Client.
type Transport interface {
	Call(context.Context, string, string, any, any, any) error
}

// New returns a regional backend. The caller owns the transport's lifetime.
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
	ctx context.Context, transport Transport, service, method string, scope any, req any,
) (T, error) {
	timeout := 5 * time.Second
	if _, ok := scope.(backend.Mutation); ok {
		timeout = 60 * time.Second
	}
	if service == "Storage" {
		switch method {
		case "CreateBucket", "DeleteBucket", "PutObject", "DeleteObject":
			timeout = 60 * time.Second
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var result T
	if err := transport.Call(ctx, service, method, scope, req, &result); err != nil {
		var zero T
		return zero, fmt.Errorf("region %s.%s: %w", service, method, err)
	}
	return result, nil
}

func (c compute) RunInstances(
	ctx context.Context, m backend.Mutation, req resource.RunInstancesRequest,
) (resource.Accepted[resource.Instance], error) {
	return call[resource.Accepted[resource.Instance]](ctx, c.transport, "Compute", "RunInstances", m, req)
}

func (c compute) StopInstances(
	ctx context.Context, m backend.Mutation, req resource.StopInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	return call[resource.Accepted[resource.InstanceStateChange]](ctx, c.transport, "Compute", "StopInstances", m, req)
}

func (c compute) StartInstances(
	ctx context.Context, m backend.Mutation, req resource.StartInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	return call[resource.Accepted[resource.InstanceStateChange]](ctx, c.transport, "Compute", "StartInstances", m, req)
}

func (c compute) TerminateInstances(
	ctx context.Context, m backend.Mutation, req resource.TerminateInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	return call[resource.Accepted[resource.InstanceStateChange]](ctx, c.transport, "Compute", "TerminateInstances", m, req)
}

func (c compute) RebootInstances(
	ctx context.Context, m backend.Mutation, req resource.RebootInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	return call[resource.Accepted[resource.InstanceStateChange]](ctx, c.transport, "Compute", "RebootInstances", m, req)
}

func (c compute) DescribeInstances(
	ctx context.Context, s backend.Scope, q resource.InstanceQuery,
) (resource.Page[resource.Instance], error) {
	return call[resource.Page[resource.Instance]](ctx, c.transport, "Compute", "DescribeInstances", s, q)
}

func (c compute) CreateTags(
	ctx context.Context, m backend.Mutation, req resource.CreateTagsRequest,
) (resource.Accepted[resource.Instance], error) {
	return call[resource.Accepted[resource.Instance]](ctx, c.transport, "Compute", "CreateTags", m, req)
}

func (c compute) DeleteTags(
	ctx context.Context, m backend.Mutation, req resource.DeleteTagsRequest,
) (resource.Accepted[resource.Instance], error) {
	return call[resource.Accepted[resource.Instance]](ctx, c.transport, "Compute", "DeleteTags", m, req)
}

func (c compute) CreateVolume(
	ctx context.Context, m backend.Mutation, req resource.CreateVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	return call[resource.Accepted[resource.Volume]](ctx, c.transport, "Compute", "CreateVolume", m, req)
}

func (c compute) TagVolumes(
	ctx context.Context, m backend.Mutation, req resource.TagVolumesRequest,
) (resource.Accepted[resource.Volume], error) {
	return call[resource.Accepted[resource.Volume]](ctx, c.transport, "Compute", "TagVolumes", m, req)
}

func (c compute) UntagVolumes(
	ctx context.Context, m backend.Mutation, req resource.UntagVolumesRequest,
) (resource.Accepted[resource.Volume], error) {
	return call[resource.Accepted[resource.Volume]](ctx, c.transport, "Compute", "UntagVolumes", m, req)
}

func (c compute) AttachVolume(
	ctx context.Context, m backend.Mutation, req resource.AttachVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	return call[resource.Accepted[resource.Volume]](ctx, c.transport, "Compute", "AttachVolume", m, req)
}

func (c compute) DetachVolume(
	ctx context.Context, m backend.Mutation, req resource.DetachVolumeRequest,
) (resource.Accepted[resource.VolumeAttachment], error) {
	return call[resource.Accepted[resource.VolumeAttachment]](ctx, c.transport, "Compute", "DetachVolume", m, req)
}

func (c compute) DeleteVolume(
	ctx context.Context, m backend.Mutation, req resource.DeleteVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	return call[resource.Accepted[resource.Volume]](ctx, c.transport, "Compute", "DeleteVolume", m, req)
}

func (c compute) ModifyVolume(
	ctx context.Context, m backend.Mutation, req resource.ModifyVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	return call[resource.Accepted[resource.Volume]](ctx, c.transport, "Compute", "ModifyVolume", m, req)
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
	ctx context.Context, m backend.Mutation, req resource.CreateKeyPairRequest,
) (resource.Accepted[resource.KeyPair], error) {
	return call[resource.Accepted[resource.KeyPair]](ctx, c.transport, "Compute", "CreateKeyPair", m, req)
}

func (c compute) DeleteKeyPair(
	ctx context.Context, m backend.Mutation, req resource.DeleteKeyPairRequest,
) (resource.Accepted[resource.KeyPair], error) {
	return call[resource.Accepted[resource.KeyPair]](ctx, c.transport, "Compute", "DeleteKeyPair", m, req)
}

func (c compute) DescribeKeyPairs(
	ctx context.Context, s backend.Scope, q resource.KeyPairQuery,
) (resource.Page[resource.KeyPair], error) {
	return call[resource.Page[resource.KeyPair]](ctx, c.transport, "Compute", "DescribeKeyPairs", s, q)
}

func (c compute) CreateSnapshot(
	ctx context.Context, m backend.Mutation, req resource.CreateSnapshotRequest,
) (resource.Accepted[resource.Snapshot], error) {
	return call[resource.Accepted[resource.Snapshot]](ctx, c.transport, "Compute", "CreateSnapshot", m, req)
}

func (c compute) DeleteSnapshot(
	ctx context.Context, m backend.Mutation, req resource.DeleteSnapshotRequest,
) (resource.Accepted[resource.Snapshot], error) {
	return call[resource.Accepted[resource.Snapshot]](ctx, c.transport, "Compute", "DeleteSnapshot", m, req)
}

func (c compute) DescribeSnapshots(
	ctx context.Context, s backend.Scope, q resource.SnapshotQuery,
) (resource.Page[resource.Snapshot], error) {
	return call[resource.Page[resource.Snapshot]](ctx, c.transport, "Compute", "DescribeSnapshots", s, q)
}

func (c compute) RegisterImage(
	ctx context.Context, m backend.Mutation, req resource.RegisterImageRequest,
) (resource.Accepted[resource.Image], error) {
	return call[resource.Accepted[resource.Image]](ctx, c.transport, "Compute", "RegisterImage", m, req)
}

func (c compute) GetOperation(
	ctx context.Context, s backend.Scope, id resource.OperationID,
) (resource.Operation, error) {
	return call[resource.Operation](ctx, c.transport, "Compute", "GetOperation", s, id)
}

func (c storage) CreateBucket(ctx context.Context, s backend.Scope, name resource.BucketName) (resource.Bucket, error) {
	return call[resource.Bucket](ctx, c.transport, "Storage", "CreateBucket", s, name)
}

func (c storage) GetBucket(ctx context.Context, s backend.Scope, name resource.BucketName) (resource.Bucket, error) {
	return call[resource.Bucket](ctx, c.transport, "Storage", "GetBucket", s, name)
}

func (c storage) ListBuckets(
	ctx context.Context, s backend.Scope, q resource.BucketQuery,
) (resource.Page[resource.Bucket], error) {
	return call[resource.Page[resource.Bucket]](ctx, c.transport, "Storage", "ListBuckets", s, q)
}

func (c storage) DeleteBucket(ctx context.Context, s backend.Scope, name resource.BucketName) error {
	_, err := call[struct{}](ctx, c.transport, "Storage", "DeleteBucket", s, name)
	return err
}

func (c storage) PutObject(
	ctx context.Context, s backend.Scope, req resource.PutObjectRequest, body io.Reader,
) (resource.Object, error) {
	data, err := io.ReadAll(io.LimitReader(body, resource.MaxObjectBytes+1))
	if err != nil {
		return resource.Object{}, fmt.Errorf("read region object: %w", err)
	}
	if len(data) > resource.MaxObjectBytes {
		return resource.Object{}, resource.TooLarge("object exceeds 4 MiB")
	}
	return call[resource.Object](ctx, c.transport, "Storage", "PutObject", s, struct {
		Request resource.PutObjectRequest `json:"request"`
		Body    []byte                    `json:"body"`
	}{req, data})
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

func (c storage) DeleteObject(
	ctx context.Context, s backend.Scope, bucket resource.BucketName, key resource.ObjectKey,
) error {
	_, err := call[struct{}](ctx, c.transport, "Storage", "DeleteObject", s, struct {
		Bucket resource.BucketName `json:"bucket"`
		Key    resource.ObjectKey  `json:"key"`
	}{bucket, key})
	return err
}

func (c storage) ListObjects(
	ctx context.Context, s backend.Scope, q resource.ObjectQuery,
) (resource.ObjectListing, error) {
	return call[resource.ObjectListing](ctx, c.transport, "Storage", "ListObjects", s, q)
}

func (c network) CreateSubnet(
	ctx context.Context, m backend.Mutation, req resource.CreateSubnetRequest,
) (resource.Accepted[resource.Subnet], error) {
	return call[resource.Accepted[resource.Subnet]](ctx, c.transport, "Network", "CreateSubnet", m, req)
}

func (c network) DescribeSubnets(
	ctx context.Context, s backend.Scope, q resource.SubnetQuery,
) (resource.Page[resource.Subnet], error) {
	return call[resource.Page[resource.Subnet]](ctx, c.transport, "Network", "DescribeSubnets", s, q)
}

func (c network) CreateVpc(
	ctx context.Context, m backend.Mutation, req resource.CreateVpcRequest,
) (resource.Accepted[resource.Vpc], error) {
	return call[resource.Accepted[resource.Vpc]](ctx, c.transport, "Network", "CreateVpc", m, req)
}

func (c network) DeleteVpc(
	ctx context.Context, m backend.Mutation, req resource.DeleteVpcRequest,
) (resource.Accepted[resource.Vpc], error) {
	return call[resource.Accepted[resource.Vpc]](ctx, c.transport, "Network", "DeleteVpc", m, req)
}

func (c network) DescribeVpcs(
	ctx context.Context, s backend.Scope, q resource.VpcQuery,
) (resource.Page[resource.Vpc], error) {
	return call[resource.Page[resource.Vpc]](ctx, c.transport, "Network", "DescribeVpcs", s, q)
}

func (c network) TagVpcs(
	ctx context.Context, m backend.Mutation, req resource.TagVpcsRequest,
) (resource.Accepted[resource.Vpc], error) {
	return call[resource.Accepted[resource.Vpc]](ctx, c.transport, "Network", "TagVpcs", m, req)
}

func (c network) TagSubnets(
	ctx context.Context, m backend.Mutation, req resource.TagSubnetsRequest,
) (resource.Accepted[resource.Subnet], error) {
	return call[resource.Accepted[resource.Subnet]](ctx, c.transport, "Network", "TagSubnets", m, req)
}

func (c network) UntagVpcs(
	ctx context.Context, m backend.Mutation, req resource.UntagVpcsRequest,
) (resource.Accepted[resource.Vpc], error) {
	return call[resource.Accepted[resource.Vpc]](ctx, c.transport, "Network", "UntagVpcs", m, req)
}

func (c network) UntagSubnets(
	ctx context.Context, m backend.Mutation, req resource.UntagSubnetsRequest,
) (resource.Accepted[resource.Subnet], error) {
	return call[resource.Accepted[resource.Subnet]](ctx, c.transport, "Network", "UntagSubnets", m, req)
}

func (c network) CreateSecurityGroup(
	ctx context.Context, m backend.Mutation, req resource.CreateSecurityGroupRequest,
) (resource.Accepted[resource.SecurityGroup], error) {
	return call[resource.Accepted[resource.SecurityGroup]](ctx, c.transport, "Network", "CreateSecurityGroup", m, req)
}

func (c network) DeleteSecurityGroup(
	ctx context.Context, m backend.Mutation, req resource.DeleteSecurityGroupRequest,
) (resource.Accepted[resource.SecurityGroup], error) {
	return call[resource.Accepted[resource.SecurityGroup]](ctx, c.transport, "Network", "DeleteSecurityGroup", m, req)
}

func (c network) DescribeSecurityGroups(
	ctx context.Context, s backend.Scope, q resource.SecurityGroupQuery,
) (resource.Page[resource.SecurityGroup], error) {
	return call[resource.Page[resource.SecurityGroup]](ctx, c.transport, "Network", "DescribeSecurityGroups", s, q)
}

func (c network) AuthorizeSecurityGroupIngress(
	ctx context.Context, m backend.Mutation, req resource.AuthorizeSecurityGroupIngressRequest,
) (resource.Accepted[resource.SecurityGroup], error) {
	return call[resource.Accepted[resource.SecurityGroup]](
		ctx, c.transport, "Network", "AuthorizeSecurityGroupIngress", m, req)
}

func (c network) RevokeSecurityGroupIngress(
	ctx context.Context, m backend.Mutation, req resource.RevokeSecurityGroupIngressRequest,
) (resource.Accepted[resource.SecurityGroup], error) {
	return call[resource.Accepted[resource.SecurityGroup]](
		ctx, c.transport, "Network", "RevokeSecurityGroupIngress", m, req)
}

func (c network) DeleteSubnet(
	ctx context.Context, m backend.Mutation, req resource.DeleteSubnetRequest,
) (resource.Accepted[resource.Subnet], error) {
	return call[resource.Accepted[resource.Subnet]](ctx, c.transport, "Network", "DeleteSubnet", m, req)
}

func (c network) AllocateAddress(
	ctx context.Context, m backend.Mutation, req resource.AllocateAddressRequest,
) (resource.Accepted[resource.Address], error) {
	return call[resource.Accepted[resource.Address]](ctx, c.transport, "Network", "AllocateAddress", m, req)
}

func (c network) ReleaseAddress(
	ctx context.Context, m backend.Mutation, req resource.ReleaseAddressRequest,
) (resource.Accepted[resource.Address], error) {
	return call[resource.Accepted[resource.Address]](ctx, c.transport, "Network", "ReleaseAddress", m, req)
}

func (c network) DescribeAddresses(
	ctx context.Context, s backend.Scope, q resource.AddressQuery,
) (resource.Page[resource.Address], error) {
	return call[resource.Page[resource.Address]](ctx, c.transport, "Network", "DescribeAddresses", s, q)
}

func (c network) AssociateAddress(
	ctx context.Context, m backend.Mutation, req resource.AssociateAddressRequest,
) (resource.Accepted[resource.Address], error) {
	return call[resource.Accepted[resource.Address]](ctx, c.transport, "Network", "AssociateAddress", m, req)
}

func (c network) DisassociateAddress(
	ctx context.Context, m backend.Mutation, req resource.DisassociateAddressRequest,
) (resource.Accepted[resource.Address], error) {
	return call[resource.Accepted[resource.Address]](ctx, c.transport, "Network", "DisassociateAddress", m, req)
}

func (c network) GetOperation(
	ctx context.Context, s backend.Scope, id resource.OperationID,
) (resource.Operation, error) {
	return call[resource.Operation](ctx, c.transport, "Network", "GetOperation", s, id)
}
