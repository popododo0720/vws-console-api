package cloud

import (
	"context"
	"errors"
	"io"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// RunInstances accepts a launch and returns the operation.
func (s *Service) RunInstances(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.RunInstancesRequest) (resource.Accepted[resource.Instance], error) {
	return mutate(ctx, s, c, token, req, s.backends.Compute.RunInstances)
}

// StopInstances accepts a stop and returns the operation.
// A zero token is filled here. RunInstances still requires one, because a
// token minted inside mutate would make every retry a new launch.
func (s *Service) StopInstances(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.StopInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Compute.StopInstances)
}

// StartInstances accepts a start and returns the operation.
func (s *Service) StartInstances(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.StartInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Compute.StartInstances)
}

// TerminateInstances accepts a terminate and returns the operation.
func (s *Service) TerminateInstances(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.TerminateInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Compute.TerminateInstances)
}

// CreateVolume accepts a blank volume and returns the operation.
func (s *Service) CreateVolume(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.CreateVolumeRequest) (resource.Accepted[resource.Volume], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Compute.CreateVolume)
}

// AttachVolume accepts an attachment and returns the operation.
func (s *Service) AttachVolume(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.AttachVolumeRequest) (resource.Accepted[resource.Volume], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Compute.AttachVolume)
}

// DeleteVolume accepts a delete and returns the operation.
func (s *Service) DeleteVolume(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.DeleteVolumeRequest) (resource.Accepted[resource.Volume], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Compute.DeleteVolume)
}

// ModifyVolume accepts a size change and returns the operation.
func (s *Service) ModifyVolume(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.ModifyVolumeRequest) (resource.Accepted[resource.Volume], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Compute.ModifyVolume)
}

// CreateTags accepts tags for instances and returns the operation.
func (s *Service) CreateTags(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.CreateTagsRequest) (resource.Accepted[resource.Instance], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Compute.CreateTags)
}

// DescribeVolumes lists volumes the caller owns.
func (s *Service) DescribeVolumes(ctx context.Context, c resource.Caller, q resource.VolumeQuery) (resource.Page[resource.Volume], error) {
	return readPage(ctx, c, q, s.backends.Compute.DescribeVolumes)
}

// DescribeImages lists images the caller can launch.
func (s *Service) DescribeImages(ctx context.Context, c resource.Caller, q resource.ImageQuery) (resource.Page[resource.Image], error) {
	return readPage(ctx, c, q, s.backends.Compute.DescribeImages)
}

// CreateKeyPair accepts a key pair and returns the operation. The private key
// is only on this result.
func (s *Service) CreateKeyPair(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.CreateKeyPairRequest) (resource.Accepted[resource.KeyPair], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Compute.CreateKeyPair)
}

// DeleteKeyPair accepts a delete and returns the operation.
func (s *Service) DeleteKeyPair(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.DeleteKeyPairRequest) (resource.Accepted[resource.KeyPair], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Compute.DeleteKeyPair)
}

// DescribeKeyPairs lists key pairs the caller owns.
func (s *Service) DescribeKeyPairs(ctx context.Context, c resource.Caller, q resource.KeyPairQuery) (resource.Page[resource.KeyPair], error) {
	return readPage(ctx, c, q, s.backends.Compute.DescribeKeyPairs)
}

// CreateSnapshot accepts a snapshot and returns the operation.
func (s *Service) CreateSnapshot(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.CreateSnapshotRequest) (resource.Accepted[resource.Snapshot], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Compute.CreateSnapshot)
}

// DeleteSnapshot accepts a delete and returns the operation.
func (s *Service) DeleteSnapshot(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.DeleteSnapshotRequest) (resource.Accepted[resource.Snapshot], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Compute.DeleteSnapshot)
}

// DescribeSnapshots lists snapshots the caller owns.
func (s *Service) DescribeSnapshots(ctx context.Context, c resource.Caller, q resource.SnapshotQuery) (resource.Page[resource.Snapshot], error) {
	return readPage(ctx, c, q, s.backends.Compute.DescribeSnapshots)
}

// DescribeInstances lists instances the caller owns.
func (s *Service) DescribeInstances(ctx context.Context, c resource.Caller, q resource.InstanceQuery) (resource.Page[resource.Instance], error) {
	page, err := readPage(ctx, c, q, s.backends.Compute.DescribeInstances)
	if err != nil || len(page.Items) == 0 {
		return page, err
	}
	if err := s.fillPublicIPs(ctx, c, page.Items); err != nil {
		return resource.Page[resource.Instance]{}, err
	}
	return page, nil
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
// EC2 has no ClientToken on this action. An empty token is derived from the
// normalized request, the same place other actions call fillToken, so a retry
// is the original subnet instead of a second one.
func (s *Service) CreateSubnet(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.CreateSubnetRequest) (resource.Accepted[resource.Subnet], error) {
	token, req, err := fillTokenFromRequest(c, token, req)
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Network.CreateSubnet)
}

// DeleteSubnet accepts a delete and returns the operation.
func (s *Service) DeleteSubnet(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.DeleteSubnetRequest) (resource.Accepted[resource.Subnet], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Network.DeleteSubnet)
}

// DescribeSubnets lists subnets the caller owns.
func (s *Service) DescribeSubnets(ctx context.Context, c resource.Caller, q resource.SubnetQuery) (resource.Page[resource.Subnet], error) {
	return readPage(ctx, c, q, s.backends.Network.DescribeSubnets)
}

// CreateVpc accepts a VPC and returns the operation.
func (s *Service) CreateVpc(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.CreateVpcRequest) (resource.Accepted[resource.Vpc], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Network.CreateVpc)
}

// DeleteVpc accepts a delete and returns the operation.
func (s *Service) DeleteVpc(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.DeleteVpcRequest) (resource.Accepted[resource.Vpc], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Network.DeleteVpc)
}

// DescribeVpcs lists VPCs the caller owns.
func (s *Service) DescribeVpcs(ctx context.Context, c resource.Caller, q resource.VpcQuery) (resource.Page[resource.Vpc], error) {
	return readPage(ctx, c, q, s.backends.Network.DescribeVpcs)
}

// CreateSecurityGroup accepts a group and returns the operation.
func (s *Service) CreateSecurityGroup(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.CreateSecurityGroupRequest) (resource.Accepted[resource.SecurityGroup], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Network.CreateSecurityGroup)
}

// DeleteSecurityGroup accepts a delete and returns the operation.
func (s *Service) DeleteSecurityGroup(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.DeleteSecurityGroupRequest) (resource.Accepted[resource.SecurityGroup], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Network.DeleteSecurityGroup)
}

// DescribeSecurityGroups lists security groups the caller owns.
func (s *Service) DescribeSecurityGroups(ctx context.Context, c resource.Caller, q resource.SecurityGroupQuery) (resource.Page[resource.SecurityGroup], error) {
	return readPage(ctx, c, q, s.backends.Network.DescribeSecurityGroups)
}

// AllocateAddress accepts an allocation and returns the operation.
func (s *Service) AllocateAddress(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.AllocateAddressRequest) (resource.Accepted[resource.Address], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Network.AllocateAddress)
}

// ReleaseAddress accepts a release and returns the operation.
func (s *Service) ReleaseAddress(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.ReleaseAddressRequest) (resource.Accepted[resource.Address], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Network.ReleaseAddress)
}

// AssociateAddress attaches an address to an instance and returns the operation.
func (s *Service) AssociateAddress(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.AssociateAddressRequest) (resource.Accepted[resource.Address], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Network.AssociateAddress)
}

// DisassociateAddress detaches an address and returns the operation.
func (s *Service) DisassociateAddress(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.DisassociateAddressRequest) (resource.Accepted[resource.Address], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.Address]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Network.DisassociateAddress)
}

// DescribeAddresses lists addresses the caller owns.
func (s *Service) DescribeAddresses(ctx context.Context, c resource.Caller, q resource.AddressQuery) (resource.Page[resource.Address], error) {
	return readPage(ctx, c, q, s.backends.Network.DescribeAddresses)
}

// AuthorizeSecurityGroupIngress accepts one inbound rule and returns the operation.
func (s *Service) AuthorizeSecurityGroupIngress(ctx context.Context, c resource.Caller, token resource.ClientToken, req resource.AuthorizeSecurityGroupIngressRequest) (resource.Accepted[resource.SecurityGroup], error) {
	token, err := fillToken(token)
	if err != nil {
		return resource.Accepted[resource.SecurityGroup]{}, err
	}
	return mutate(ctx, s, c, token, req, s.backends.Network.AuthorizeSecurityGroupIngress)
}

// fillToken mints a token only for actions whose AWS shape omits ClientToken.
func fillToken(token resource.ClientToken) (resource.ClientToken, error) {
	if !token.IsZero() {
		return token, nil
	}
	minted, err := resource.NewClientToken(nil)
	if err != nil {
		return resource.ClientToken{}, err
	}
	return minted, nil
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
		return resource.Object{}, nil, errors.Join(err, rc.Close())
	}
	return meta, rc, nil
}

// ListObjects lists keys in a bucket the caller owns. One storage call
// returns the page; the backend reads however many service pages it needs.
func (s *Service) ListObjects(ctx context.Context, c resource.Caller, q resource.ObjectQuery) (resource.ObjectListing, error) {
	if err := requireCaller(c); err != nil {
		return resource.ObjectListing{}, err
	}
	q, err := q.Normalize()
	if err != nil {
		return resource.ObjectListing{}, err
	}
	listing, err := s.backends.Storage.ListObjects(ctx, scope(c), q)
	if err != nil {
		return resource.ObjectListing{}, err
	}
	for _, obj := range listing.Objects {
		if err := guardOwner(c.Account, obj); err != nil {
			return resource.ObjectListing{}, err
		}
	}
	return listing, nil
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
