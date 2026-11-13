package proxmox

import (
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Backend implements Proxmox inventory and console access.
type Backend struct {
	region          string
	cluster         string
	client          *pveclient.Client
	leader          atomic.Pointer[Leader]
	cfg             RegionConfig
	zones           []backend.Zone
	statusMu        sync.Mutex
	volumeMu        sync.Mutex
	launchMu        sync.Mutex
	finalizeMu      sync.Mutex
	instanceMu      sync.Mutex
	lastInstances   map[int]instanceSnapshot
	lastStatusError *resource.RegionStatusError
}

// Set returns the services sharing this backend.
func (b *Backend) Set() backend.Set {
	return backend.Set{Compute: b, Storage: b, Network: b, Console: b, Usage: b}
}

// RegionCapabilities declares regional action support.
func (b *Backend) RegionCapabilities(ctx context.Context, region string) (resource.RegionCapabilities, error) {
	if region != b.region && region != "all" {
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
	zones, err := b.availabilityZones(ctx)
	if err != nil {
		return resource.RegionCapabilities{}, err
	}
	status, err := b.Status(ctx)
	if err != nil {
		return resource.RegionCapabilities{}, err
	}
	cluster := &resource.RegionCluster{
		Name: b.cluster, Quorate: status.Quorate, PVERelease: status.PVERelease,
	}
	if status.Leader != nil {
		cluster.Leader = *status.Leader
	}
	doc := resource.RegionCapabilities{
		Region: region, Kind: resource.RegionKindProxmox,
		Cluster: cluster, Zones: zones,
		Actions: map[string]resource.ActionCapability{}, InstanceTypes: types,
		Features: resource.RegionFeatures{SnapshotScope: "vm", LiveTests: b.cfg.LiveTests, PrivateIPMode: "static"},
	}
	for _, a := range resource.Actions() {
		doc.Actions[a.CapabilityKey()] = resource.ActionCapability{
			State: resource.ActionUnsupported, ReasonCode: "ReadOnly", Reason: "read-only",
		}
	}
	for _, r := range resource.ReadActions() {
		doc.Actions[r.CapabilityKey()] = resource.ActionCapability{State: resource.ActionEmpty}
	}
	for _, key := range []string{
		"ec2:DescribeInstances", "ec2:DescribeAvailabilityZones", "ec2:DescribeRegions",
		"ec2:DescribeVolumes", "ec2:DescribeSnapshots", "ec2:DescribeTags", "ec2:DescribeImages",
	} {
		doc.Actions[key] = resource.ActionCapability{State: resource.ActionSupported}
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
	if !b.cfg.ReadOnly {
		doc.Actions["ec2:RunInstances"] = resource.ActionCapability{
			State: resource.ActionPartial, ReasonCode: "LaunchDefaults",
			Reason: "user data, extra disks and custom root sizes are not supported",
		}
		doc.Actions["vws:OpenConsole"] = resource.ActionCapability{State: resource.ActionSupported}
		doc.Actions["ec2:CreateVolume"] = resource.ActionCapability{
			State: resource.ActionPartial, ReasonCode: "NoSnapshotSource",
			Reason: "blank volumes only; volume tags must encode within 128 bytes",
		}
		doc.Actions["ec2:DeleteVolume"] = resource.ActionCapability{State: resource.ActionSupported}
		doc.Actions["ec2:AttachVolume"] = resource.ActionCapability{State: resource.ActionSupported}
		doc.Actions["ec2:DetachVolume"] = resource.ActionCapability{
			State: resource.ActionPartial, ReasonCode: "StoppedInstance",
			Reason: "detach requires a stopped instance; config hot-unplug to unused disks is not supported",
		}
		for _, key := range []string{
			"ec2:StartInstances", "ec2:StopInstances", "ec2:RebootInstances", "ec2:TerminateInstances",
		} {
			doc.Actions[key] = resource.ActionCapability{State: resource.ActionSupported}
		}
		doc.Features.OperationScope = "first-task"
		doc.Actions["ec2:TerminateInstances"] = resource.ActionCapability{
			State: resource.ActionPartial, ReasonCode: "RetainedDisks",
			Reason: "retained disks require holder support",
		}
		for _, key := range []string{"ec2:CreateTags", "ec2:DeleteTags"} {
			doc.Actions[key] = resource.ActionCapability{
				State:      resource.ActionPartial,
				ReasonCode: "InstanceVolumeTags",
				Reason:     "instances and volumes only; volume tags require at most 128 encoded characters",
			}
		}
		doc.Actions["ec2:CreateSnapshot"] = resource.ActionCapability{State: resource.ActionSupported}
	}
	return doc, nil
}

// ModifyVolume is unavailable in the phase-one backend.
func (b *Backend) ModifyVolume(
	ctx context.Context, m backend.Mutation, req resource.ModifyVolumeRequest,
) (resource.Accepted[resource.Volume], error) {
	return resource.Accepted[resource.Volume]{}, resource.Unsupported("ModifyVolume", "read-only")
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

// DeleteSnapshot is unavailable in the phase-one backend.
func (b *Backend) DeleteSnapshot(
	ctx context.Context, m backend.Mutation, req resource.DeleteSnapshotRequest,
) (resource.Accepted[resource.Snapshot], error) {
	return resource.Accepted[resource.Snapshot]{}, resource.Unsupported("DeleteSnapshot", "read-only")
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
