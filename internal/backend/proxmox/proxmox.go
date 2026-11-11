package proxmox

import (
	"context"
	"io"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Backend is the phase-one read-only Proxmox backend.
type Backend struct {
	region  string
	cluster string
	client  *pveclient.Client
	cfg     RegionConfig
}

// Set returns the three services sharing this backend.
func (b *Backend) Set() backend.Set { return backend.Set{Compute: b, Storage: b, Network: b} }

// RegionCapabilities declares the regional catalog, bridge inventory and disabled writes.
func (b *Backend) RegionCapabilities(ctx context.Context, region string) (resource.RegionCapabilities, error) {
	if region != b.region {
		return resource.RegionCapabilities{}, resource.Invalid("region", "not served by this backend")
	}
	types, err := b.instanceTypes(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return resource.RegionCapabilities{}, err
		}
		// Node capacity limits the catalog, not the action policy used by every kernel gate.
		types = []resource.RegionInstanceType{}
	}
	doc := resource.RegionCapabilities{
		Region: region, Kind: resource.RegionKindProxmox,
		Cluster: &resource.RegionCluster{Name: b.cluster}, Zones: []resource.RegionZone{},
		Actions: map[string]resource.ActionCapability{}, InstanceTypes: types,
	}
	for _, a := range resource.Actions() {
		doc.Actions[a.CapabilityKey()] = resource.ActionCapability{
			State: resource.ActionUnsupported, ReasonCode: "ReadOnly", Reason: "read-only",
		}
	}
	for _, r := range resource.ReadActions() {
		doc.Actions[r.CapabilityKey()] = resource.ActionCapability{State: resource.ActionEmpty}
	}
	for _, key := range []string{"ec2:DescribeVpcs", "ec2:DescribeSubnets"} {
		doc.Actions[key] = resource.ActionCapability{
			State: resource.ActionPartial, ReasonCode: "BridgeInventory",
			Reason: "bridge inventory; SDN inventory is not yet served",
		}
	}
	for _, key := range []string{"ec2:DescribeRouteTables", "ec2:DescribeVolumesModifications"} {
		doc.Actions[key] = resource.ActionCapability{State: resource.ActionEmpty}
	}
	return doc, nil
}

// GetOperation reports a missing resource in the empty inventory.
func (b *Backend) GetOperation(
	ctx context.Context, s backend.Scope, id resource.OperationID,
) (resource.Operation, error) {
	return resource.Operation{}, resource.NotFound(resource.KindOperation, id.String())
}

// RunInstances is unavailable in the phase-one backend.
func (b *Backend) RunInstances(
	ctx context.Context, m backend.Mutation, req resource.RunInstancesRequest,
) (resource.Accepted[resource.Instance], error) {
	return resource.Accepted[resource.Instance]{}, resource.Unsupported("RunInstances", "read-only")
}

// StopInstances is unavailable in the phase-one backend.
func (b *Backend) StopInstances(
	ctx context.Context, m backend.Mutation, req resource.StopInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	return resource.Accepted[resource.InstanceStateChange]{}, resource.Unsupported("StopInstances", "read-only")
}

// RebootInstances is unavailable in the phase-one backend.
func (b *Backend) RebootInstances(
	ctx context.Context, m backend.Mutation, req resource.RebootInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	return resource.Accepted[resource.InstanceStateChange]{}, resource.Unsupported("RebootInstances", "read-only")
}

// StartInstances is unavailable in the phase-one backend.
func (b *Backend) StartInstances(
	ctx context.Context, m backend.Mutation, req resource.StartInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	return resource.Accepted[resource.InstanceStateChange]{}, resource.Unsupported("StartInstances", "read-only")
}

// TerminateInstances is unavailable in the phase-one backend.
func (b *Backend) TerminateInstances(
	ctx context.Context, m backend.Mutation, req resource.TerminateInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	return resource.Accepted[resource.InstanceStateChange]{}, resource.Unsupported("TerminateInstances", "read-only")
}

// DescribeInstances answers the phase-one empty inventory.
func (b *Backend) DescribeInstances(
	ctx context.Context, s backend.Scope, q resource.InstanceQuery,
) (resource.Page[resource.Instance], error) {
	return resource.Page[resource.Instance]{}, nil
}

// CreateTags is unavailable in the phase-one backend.
func (b *Backend) CreateTags(
	ctx context.Context, m backend.Mutation, req resource.CreateTagsRequest,
) (resource.Accepted[resource.Instance], error) {
	return resource.Accepted[resource.Instance]{}, resource.Unsupported("CreateTags", "read-only")
}

// DeleteTags is unavailable in the phase-one backend.
func (b *Backend) DeleteTags(
	ctx context.Context, m backend.Mutation, req resource.DeleteTagsRequest,
) (resource.Accepted[resource.Instance], error) {
	return resource.Accepted[resource.Instance]{}, resource.Unsupported("DeleteTags", "read-only")
}

// CreateVolume is unavailable in the phase-one backend.
func (b *Backend) CreateVolume(
	ctx context.Context, m backend.Mutation, req resource.CreateVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	return resource.Accepted[resource.Volume]{}, resource.Unsupported("CreateVolume", "read-only")
}

// TagVolumes is unavailable in the phase-one backend.
func (b *Backend) TagVolumes(
	ctx context.Context, m backend.Mutation, req resource.TagVolumesRequest,
) (resource.Accepted[resource.Volume], error) {
	return resource.Accepted[resource.Volume]{}, resource.Unsupported("TagVolumes", "read-only")
}

// AttachVolume is unavailable in the phase-one backend.
func (b *Backend) AttachVolume(
	ctx context.Context, m backend.Mutation, req resource.AttachVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	return resource.Accepted[resource.Volume]{}, resource.Unsupported("AttachVolume", "read-only")
}

// DetachVolume is unavailable in the phase-one backend.
func (b *Backend) DetachVolume(
	ctx context.Context, m backend.Mutation, req resource.DetachVolumeRequest,
) (resource.Accepted[resource.VolumeAttachment], error) {
	return resource.Accepted[resource.VolumeAttachment]{}, resource.Unsupported("DetachVolume", "read-only")
}

// DeleteVolume is unavailable in the phase-one backend.
func (b *Backend) DeleteVolume(
	ctx context.Context, m backend.Mutation, req resource.DeleteVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	return resource.Accepted[resource.Volume]{}, resource.Unsupported("DeleteVolume", "read-only")
}

// ModifyVolume is unavailable in the phase-one backend.
func (b *Backend) ModifyVolume(
	ctx context.Context, m backend.Mutation, req resource.ModifyVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	return resource.Accepted[resource.Volume]{}, resource.Unsupported("ModifyVolume", "read-only")
}

// DescribeVolumes answers the phase-one empty inventory.
func (b *Backend) DescribeVolumes(
	ctx context.Context, s backend.Scope, q resource.VolumeQuery,
) (resource.Page[resource.Volume], error) {
	return resource.Page[resource.Volume]{}, nil
}

// DescribeImages answers the phase-one empty inventory.
func (b *Backend) DescribeImages(
	ctx context.Context, s backend.Scope, q resource.ImageQuery,
) (resource.Page[resource.Image], error) {
	return resource.Page[resource.Image]{}, nil
}

// CreateKeyPair is unavailable in the phase-one backend.
func (b *Backend) CreateKeyPair(
	ctx context.Context, m backend.Mutation, req resource.CreateKeyPairRequest,
) (resource.Accepted[resource.KeyPair], error) {
	return resource.Accepted[resource.KeyPair]{}, resource.Unsupported("CreateKeyPair", "read-only")
}

// DeleteKeyPair is unavailable in the phase-one backend.
func (b *Backend) DeleteKeyPair(
	ctx context.Context, m backend.Mutation, req resource.DeleteKeyPairRequest,
) (resource.Accepted[resource.KeyPair], error) {
	return resource.Accepted[resource.KeyPair]{}, resource.Unsupported("DeleteKeyPair", "read-only")
}

// DescribeKeyPairs answers the phase-one empty inventory.
func (b *Backend) DescribeKeyPairs(
	ctx context.Context, s backend.Scope, q resource.KeyPairQuery,
) (resource.Page[resource.KeyPair], error) {
	return resource.Page[resource.KeyPair]{}, nil
}

// CreateSnapshot is unavailable in the phase-one backend.
func (b *Backend) CreateSnapshot(
	ctx context.Context, m backend.Mutation, req resource.CreateSnapshotRequest,
) (resource.Accepted[resource.Snapshot], error) {
	return resource.Accepted[resource.Snapshot]{}, resource.Unsupported("CreateSnapshot", "read-only")
}

// DeleteSnapshot is unavailable in the phase-one backend.
func (b *Backend) DeleteSnapshot(
	ctx context.Context, m backend.Mutation, req resource.DeleteSnapshotRequest,
) (resource.Accepted[resource.Snapshot], error) {
	return resource.Accepted[resource.Snapshot]{}, resource.Unsupported("DeleteSnapshot", "read-only")
}

// DescribeSnapshots answers the phase-one empty inventory.
func (b *Backend) DescribeSnapshots(
	ctx context.Context, s backend.Scope, q resource.SnapshotQuery,
) (resource.Page[resource.Snapshot], error) {
	return resource.Page[resource.Snapshot]{}, nil
}

// RegisterImage is unavailable in the phase-one backend.
func (b *Backend) RegisterImage(
	ctx context.Context, m backend.Mutation, req resource.RegisterImageRequest,
) (resource.Accepted[resource.Image], error) {
	return resource.Accepted[resource.Image]{}, resource.Unsupported("RegisterImage", "read-only")
}

// CreateBucket is unavailable in the phase-one backend.
func (b *Backend) CreateBucket(context.Context, backend.Scope, resource.BucketName) (resource.Bucket, error) {
	return resource.Bucket{}, resource.Unsupported("CreateBucket", "read-only")
}

// GetBucket reports a missing resource in the empty inventory.
func (b *Backend) GetBucket(ctx context.Context, s backend.Scope, name resource.BucketName) (resource.Bucket, error) {
	return resource.Bucket{}, resource.NotFound(resource.KindBucket, name.String())
}

// ListBuckets answers the phase-one empty inventory.
func (b *Backend) ListBuckets(
	ctx context.Context, s backend.Scope, q resource.BucketQuery,
) (resource.Page[resource.Bucket], error) {
	return resource.Page[resource.Bucket]{}, nil
}

// DeleteBucket is unavailable in the phase-one backend.
func (b *Backend) DeleteBucket(context.Context, backend.Scope, resource.BucketName) error {
	return resource.Unsupported("DeleteBucket", "read-only")
}

// PutObject is unavailable in the phase-one backend.
func (b *Backend) PutObject(
	ctx context.Context, s backend.Scope, req resource.PutObjectRequest, body io.Reader,
) (resource.Object, error) {
	return resource.Object{}, resource.Unsupported("PutObject", "read-only")
}

// GetObject reports a missing resource in the empty inventory.
func (b *Backend) GetObject(
	ctx context.Context, s backend.Scope, req resource.GetObjectRequest,
) (resource.Object, io.ReadCloser, error) {
	return resource.Object{}, nil, resource.NotFound(resource.KindObject, req.Key.String())
}

// DeleteObject is unavailable in the phase-one backend.
func (b *Backend) DeleteObject(context.Context, backend.Scope, resource.BucketName, resource.ObjectKey) error {
	return resource.Unsupported("DeleteObject", "read-only")
}

// ListObjects answers the phase-one empty inventory.
func (b *Backend) ListObjects(context.Context, backend.Scope, resource.ObjectQuery) (resource.ObjectListing, error) {
	return resource.ObjectListing{}, nil
}

// CreateSubnet is unavailable in the phase-one backend.
func (b *Backend) CreateSubnet(
	ctx context.Context, m backend.Mutation, req resource.CreateSubnetRequest,
) (resource.Accepted[resource.Subnet], error) {
	return resource.Accepted[resource.Subnet]{}, resource.Unsupported("CreateSubnet", "read-only")
}

// CreateVpc is unavailable in the phase-one backend.
func (b *Backend) CreateVpc(
	ctx context.Context, m backend.Mutation, req resource.CreateVpcRequest,
) (resource.Accepted[resource.Vpc], error) {
	return resource.Accepted[resource.Vpc]{}, resource.Unsupported("CreateVpc", "read-only")
}

// DeleteVpc is unavailable in the phase-one backend.
func (b *Backend) DeleteVpc(
	ctx context.Context, m backend.Mutation, req resource.DeleteVpcRequest,
) (resource.Accepted[resource.Vpc], error) {
	return resource.Accepted[resource.Vpc]{}, resource.Unsupported("DeleteVpc", "read-only")
}

// TagVpcs is unavailable in the phase-one backend.
func (b *Backend) TagVpcs(
	ctx context.Context, m backend.Mutation, req resource.TagVpcsRequest,
) (resource.Accepted[resource.Vpc], error) {
	return resource.Accepted[resource.Vpc]{}, resource.Unsupported("TagVpcs", "read-only")
}

// TagSubnets is unavailable in the phase-one backend.
func (b *Backend) TagSubnets(
	ctx context.Context, m backend.Mutation, req resource.TagSubnetsRequest,
) (resource.Accepted[resource.Subnet], error) {
	return resource.Accepted[resource.Subnet]{}, resource.Unsupported("TagSubnets", "read-only")
}

// UntagVpcs is unavailable in the phase-one backend.
func (b *Backend) UntagVpcs(
	ctx context.Context, m backend.Mutation, req resource.UntagVpcsRequest,
) (resource.Accepted[resource.Vpc], error) {
	return resource.Accepted[resource.Vpc]{}, resource.Unsupported("UntagVpcs", "read-only")
}

// UntagSubnets is unavailable in the phase-one backend.
func (b *Backend) UntagSubnets(
	ctx context.Context, m backend.Mutation, req resource.UntagSubnetsRequest,
) (resource.Accepted[resource.Subnet], error) {
	return resource.Accepted[resource.Subnet]{}, resource.Unsupported("UntagSubnets", "read-only")
}

// CreateSecurityGroup is unavailable in the phase-one backend.
func (b *Backend) CreateSecurityGroup(
	ctx context.Context, m backend.Mutation, req resource.CreateSecurityGroupRequest,
) (resource.Accepted[resource.SecurityGroup], error) {
	return resource.Accepted[resource.SecurityGroup]{}, resource.Unsupported("CreateSecurityGroup", "read-only")
}

// DeleteSecurityGroup is unavailable in the phase-one backend.
func (b *Backend) DeleteSecurityGroup(
	ctx context.Context, m backend.Mutation, req resource.DeleteSecurityGroupRequest,
) (resource.Accepted[resource.SecurityGroup], error) {
	return resource.Accepted[resource.SecurityGroup]{}, resource.Unsupported("DeleteSecurityGroup", "read-only")
}

// DescribeSecurityGroups answers the phase-one empty inventory.
func (b *Backend) DescribeSecurityGroups(
	ctx context.Context, s backend.Scope, q resource.SecurityGroupQuery,
) (resource.Page[resource.SecurityGroup], error) {
	return resource.Page[resource.SecurityGroup]{}, nil
}

// AuthorizeSecurityGroupIngress is unavailable in the phase-one backend.
func (b *Backend) AuthorizeSecurityGroupIngress(
	ctx context.Context, m backend.Mutation, req resource.AuthorizeSecurityGroupIngressRequest,
) (resource.Accepted[resource.SecurityGroup], error) {
	return resource.Accepted[resource.SecurityGroup]{}, resource.Unsupported("AuthorizeSecurityGroupIngress", "read-only")
}

// RevokeSecurityGroupIngress is unavailable in the phase-one backend.
func (b *Backend) RevokeSecurityGroupIngress(
	ctx context.Context, m backend.Mutation, req resource.RevokeSecurityGroupIngressRequest,
) (resource.Accepted[resource.SecurityGroup], error) {
	return resource.Accepted[resource.SecurityGroup]{}, resource.Unsupported("RevokeSecurityGroupIngress", "read-only")
}

// DeleteSubnet is unavailable in the phase-one backend.
func (b *Backend) DeleteSubnet(
	ctx context.Context, m backend.Mutation, req resource.DeleteSubnetRequest,
) (resource.Accepted[resource.Subnet], error) {
	return resource.Accepted[resource.Subnet]{}, resource.Unsupported("DeleteSubnet", "read-only")
}

// AllocateAddress is unavailable in the phase-one backend.
func (b *Backend) AllocateAddress(
	ctx context.Context, m backend.Mutation, req resource.AllocateAddressRequest,
) (resource.Accepted[resource.Address], error) {
	return resource.Accepted[resource.Address]{}, resource.Unsupported("AllocateAddress", "read-only")
}

// ReleaseAddress is unavailable in the phase-one backend.
func (b *Backend) ReleaseAddress(
	ctx context.Context, m backend.Mutation, req resource.ReleaseAddressRequest,
) (resource.Accepted[resource.Address], error) {
	return resource.Accepted[resource.Address]{}, resource.Unsupported("ReleaseAddress", "read-only")
}

// DescribeAddresses answers the phase-one empty inventory.
func (b *Backend) DescribeAddresses(
	ctx context.Context, s backend.Scope, q resource.AddressQuery,
) (resource.Page[resource.Address], error) {
	return resource.Page[resource.Address]{}, nil
}

// AssociateAddress is unavailable in the phase-one backend.
func (b *Backend) AssociateAddress(
	ctx context.Context, m backend.Mutation, req resource.AssociateAddressRequest,
) (resource.Accepted[resource.Address], error) {
	return resource.Accepted[resource.Address]{}, resource.Unsupported("AssociateAddress", "read-only")
}

// DisassociateAddress is unavailable in the phase-one backend.
func (b *Backend) DisassociateAddress(
	ctx context.Context, m backend.Mutation, req resource.DisassociateAddressRequest,
) (resource.Accepted[resource.Address], error) {
	return resource.Accepted[resource.Address]{}, resource.Unsupported("DisassociateAddress", "read-only")
}
