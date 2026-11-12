package awssdk

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (b *Backend) checkScope(s backend.Scope) error {
	if s.Region != b.region {
		return resource.Invalid("region", "not served by this backend")
	}
	if s.Account.String() != b.account {
		return resource.Invalid("account", "not served by this backend")
	}
	return nil
}

func mutationToken(m backend.Mutation) string {
	sum := sha256.Sum256([]byte(m.Account.String() + "\x00" + m.Region + "\x00" + m.Key))
	return fmt.Sprintf("%x", sum)
}

// EC2 returns resource states rather than task handles. The operation records
// successful submission; callers observe subsequent transitions through Describe.
func accepted[T resource.Owned](
	m backend.Mutation, action resource.Action, kind resource.Kind, items []T,
) (resource.Accepted[T], error) {
	sum := sha256.Sum256([]byte(mutationToken(m) + "\x00" + action.String()))
	id, err := resource.NewOperationID(resource.ServiceCompute, fmt.Sprintf("%x", sum[:20]))
	if err != nil {
		return resource.Accepted[T]{}, resource.Internal(err)
	}
	op := resource.Operation{ID: id, Action: action, OwnerID: m.Account, State: resource.OperationSucceeded}
	for _, item := range items {
		ref, err := resource.ParseRef(kind.String(), item.Identity())
		if err != nil {
			return resource.Accepted[T]{}, resource.Internal(err)
		}
		op.Targets = append(op.Targets, ref)
	}
	return resource.Accepted[T]{Operation: op, Items: items}, nil
}

func instanceIDs(ids []resource.InstanceID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

func awsTags(tags map[string]string) []types.Tag {
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]types.Tag, 0, len(tags))
	for _, key := range keys {
		out = append(out, types.Tag{Key: aws.String(key), Value: aws.String(tags[key])})
	}
	return out
}

// RunInstances binds retries to Mutation.Key through EC2's client token.
func (b *Backend) RunInstances(
	ctx context.Context, m backend.Mutation, req resource.RunInstancesRequest,
) (resource.Accepted[resource.Instance], error) {
	if err := b.checkScope(m.Scope); err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	input := &ec2.RunInstancesInput{
		ImageId: aws.String(req.ImageID.String()), InstanceType: types.InstanceType(req.InstanceType),
		MinCount: aws.Int32(int32(req.Count)), MaxCount: aws.Int32(int32(req.Count)),
		ClientToken: aws.String(mutationToken(m)),
	}
	if req.KeyName != "" {
		input.KeyName = aws.String(req.KeyName)
	}
	if req.UserData != "" {
		input.UserData = aws.String(base64.StdEncoding.EncodeToString([]byte(req.UserData)))
	}
	if len(req.NetworkInterfaces) == 0 {
		input.SubnetId = aws.String(req.SubnetID.String())
	}
	for _, nic := range req.NetworkInterfaces {
		input.NetworkInterfaces = append(input.NetworkInterfaces, types.InstanceNetworkInterfaceSpecification{
			DeviceIndex: aws.Int32(int32(nic.DeviceIndex)), SubnetId: aws.String(nic.SubnetID.String()),
		})
	}
	if len(req.Tags) != 0 {
		input.TagSpecifications = []types.TagSpecification{
			{ResourceType: types.ResourceTypeInstance, Tags: awsTags(req.Tags)},
		}
	}
	if req.RootVolumeType != "" || req.RootVolumeSize != 0 ||
		req.RootIops != 0 || req.RootThroughput != 0 || req.RootVolumeKept {
		images, err := b.client.DescribeImages(ctx, &ec2.DescribeImagesInput{ImageIds: []string{req.ImageID.String()}})
		if err != nil {
			return resource.Accepted[resource.Instance]{}, awsError(err)
		}
		if len(images.Images) != 1 || aws.ToString(images.Images[0].RootDeviceName) == "" {
			return resource.Accepted[resource.Instance]{}, resource.Invalid("imageId", "image has no root device")
		}
		ebs := &types.EbsBlockDevice{
			DeleteOnTermination: aws.Bool(!req.RootVolumeKept), VolumeType: types.VolumeType(req.RootVolumeType),
		}
		if req.RootVolumeSize != 0 {
			ebs.VolumeSize = aws.Int32(int32(req.RootVolumeSize))
		}
		if req.RootIops != 0 {
			ebs.Iops = aws.Int32(int32(req.RootIops))
		}
		if req.RootThroughput != 0 {
			ebs.Throughput = aws.Int32(int32(req.RootThroughput))
		}
		input.BlockDeviceMappings = append(input.BlockDeviceMappings, types.BlockDeviceMapping{
			DeviceName: images.Images[0].RootDeviceName, Ebs: ebs,
		})
	}
	for _, volume := range req.ExtraVolumes {
		ebs := &types.EbsBlockDevice{
			VolumeType: types.VolumeType(volume.VolumeType()), VolumeSize: aws.Int32(int32(volume.SizeGiB)),
			DeleteOnTermination: aws.Bool(!volume.Kept),
		}
		if volume.Iops != 0 {
			ebs.Iops = aws.Int32(int32(volume.Iops))
		}
		if volume.Throughput != 0 {
			ebs.Throughput = aws.Int32(int32(volume.Throughput))
		}
		input.BlockDeviceMappings = append(input.BlockDeviceMappings, types.BlockDeviceMapping{
			DeviceName: aws.String(volume.Device), Ebs: ebs,
		})
	}
	out, err := b.client.RunInstances(ctx, input)
	if err != nil {
		return resource.Accepted[resource.Instance]{}, awsError(err)
	}
	items := make([]resource.Instance, 0, len(out.Instances))
	for _, instance := range out.Instances {
		item, err := mapInstance(instance, out.ReservationId)
		if err != nil {
			return resource.Accepted[resource.Instance]{}, resource.Internal(err)
		}
		item.OwnerID = m.Account
		items = append(items, item)
	}
	return accepted(m, req.Action(), resource.KindInstance, items)
}

func stateChanges(
	m backend.Mutation, action resource.Action, changes []types.InstanceStateChange,
) (resource.Accepted[resource.InstanceStateChange], error) {
	items := make([]resource.InstanceStateChange, 0, len(changes))
	for _, change := range changes {
		id, err := resource.Parse[resource.InstanceID](aws.ToString(change.InstanceId))
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, resource.Internal(err)
		}
		if change.PreviousState == nil || change.CurrentState == nil {
			return resource.Accepted[resource.InstanceStateChange]{}, resource.Internal(errors.New("missing AWS instance state"))
		}
		previous, previousOK := resource.ParseInstanceState(string(change.PreviousState.Name))
		current, currentOK := resource.ParseInstanceState(string(change.CurrentState.Name))
		if !previousOK || !currentOK {
			return resource.Accepted[resource.InstanceStateChange]{}, resource.Internal(errors.New("unknown AWS instance state"))
		}
		items = append(items, resource.InstanceStateChange{ID: id, OwnerID: m.Account, Previous: previous, Current: current})
	}
	return accepted(m, action, resource.KindInstance, items)
}

// StartInstances returns the transition EC2 accepted, before the instance boots.
func (b *Backend) StartInstances(
	ctx context.Context, m backend.Mutation, req resource.StartInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	if err := b.checkScope(m.Scope); err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	out, err := b.client.StartInstances(ctx, &ec2.StartInstancesInput{InstanceIds: instanceIDs(req.IDs)})
	if err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, awsError(err)
	}
	return stateChanges(m, req.Action(), out.StartingInstances)
}

// StopInstances returns the transition EC2 accepted, before shutdown completes.
func (b *Backend) StopInstances(
	ctx context.Context, m backend.Mutation, req resource.StopInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	if err := b.checkScope(m.Scope); err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	out, err := b.client.StopInstances(ctx, &ec2.StopInstancesInput{InstanceIds: instanceIDs(req.IDs)})
	if err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, awsError(err)
	}
	return stateChanges(m, req.Action(), out.StoppingInstances)
}

// TerminateInstances returns EC2's transition; AWS owns volume cleanup.
func (b *Backend) TerminateInstances(
	ctx context.Context, m backend.Mutation, req resource.TerminateInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	if err := b.checkScope(m.Scope); err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	out, err := b.client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: instanceIDs(req.IDs)})
	if err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, awsError(err)
	}
	return stateChanges(m, req.Action(), out.TerminatingInstances)
}

// RebootInstances reads states because EC2's reboot response contains none.
func (b *Backend) RebootInstances(
	ctx context.Context, m backend.Mutation, req resource.RebootInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	if err := b.checkScope(m.Scope); err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if _, err := b.client.RebootInstances(ctx, &ec2.RebootInstancesInput{InstanceIds: instanceIDs(req.IDs)}); err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, awsError(err)
	}
	page, err := b.DescribeInstances(ctx, m.Scope, resource.InstanceQuery{IDs: req.IDs})
	if err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	items := make([]resource.InstanceStateChange, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, resource.InstanceStateChange{
			ID: item.ID, OwnerID: m.Account, Previous: item.State, Current: item.State,
		})
	}
	return accepted(m, req.Action(), resource.KindInstance, items)
}

// CreateTags returns refreshed instances, including tags EC2 retained.
func (b *Backend) CreateTags(
	ctx context.Context, m backend.Mutation, req resource.CreateTagsRequest,
) (resource.Accepted[resource.Instance], error) {
	if err := b.checkScope(m.Scope); err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	input := &ec2.CreateTagsInput{Resources: instanceIDs(req.IDs), Tags: awsTags(req.Tags)}
	if _, err := b.client.CreateTags(ctx, input); err != nil {
		return resource.Accepted[resource.Instance]{}, awsError(err)
	}
	page, err := b.DescribeInstances(ctx, m.Scope, resource.InstanceQuery{IDs: req.IDs})
	if err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	return accepted(m, req.Action(), resource.KindInstance, page.Items)
}

// DeleteTags preserves the distinction between an omitted and an empty selector value.
func (b *Backend) DeleteTags(
	ctx context.Context, m backend.Mutation, req resource.DeleteTagsRequest,
) (resource.Accepted[resource.Instance], error) {
	if err := b.checkScope(m.Scope); err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	input := &ec2.DeleteTagsInput{Resources: instanceIDs(req.IDs)}
	for _, tag := range req.Tags {
		input.Tags = append(input.Tags, types.Tag{Key: aws.String(tag.Key), Value: tag.Value})
	}
	if _, err := b.client.DeleteTags(ctx, input); err != nil {
		return resource.Accepted[resource.Instance]{}, awsError(err)
	}
	page, err := b.DescribeInstances(ctx, m.Scope, resource.InstanceQuery{IDs: req.IDs})
	if err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	return accepted(m, req.Action(), resource.KindInstance, page.Items)
}

// CreateSnapshot returns the snapshot at acceptance, which may still be pending.
func (b *Backend) CreateSnapshot(
	ctx context.Context, m backend.Mutation, req resource.CreateSnapshotRequest,
) (resource.Accepted[resource.Snapshot], error) {
	if err := b.checkScope(m.Scope); err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	input := &ec2.CreateSnapshotInput{
		VolumeId: aws.String(req.VolumeID.String()), Description: aws.String(req.Description),
	}
	if len(req.Tags) != 0 {
		input.TagSpecifications = []types.TagSpecification{
			{ResourceType: types.ResourceTypeSnapshot, Tags: awsTags(req.Tags)},
		}
	}
	out, err := b.client.CreateSnapshot(ctx, input)
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, awsError(err)
	}
	id, err := resource.Parse[resource.SnapshotID](aws.ToString(out.SnapshotId))
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, resource.Internal(err)
	}
	volume, err := resource.Parse[resource.VolumeID](aws.ToString(out.VolumeId))
	if err != nil {
		return resource.Accepted[resource.Snapshot]{}, resource.Internal(err)
	}
	item := resource.Snapshot{
		ID: id, OwnerID: m.Account, VolumeID: volume, VolumeSize: int64(aws.ToInt32(out.VolumeSize)),
		State: string(out.State), Description: aws.ToString(out.Description), Tags: make(map[string]string),
	}
	for _, tag := range out.Tags {
		item.Tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return accepted(m, req.Action(), resource.KindSnapshot, []resource.Snapshot{item})
}

// DeleteSnapshot returns the deleted identity because EC2 returns no snapshot body.
func (b *Backend) DeleteSnapshot(
	ctx context.Context, m backend.Mutation, req resource.DeleteSnapshotRequest,
) (resource.Accepted[resource.Snapshot], error) {
	if err := b.checkScope(m.Scope); err != nil {
		return resource.Accepted[resource.Snapshot]{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	input := &ec2.DeleteSnapshotInput{SnapshotId: aws.String(req.ID.String())}
	if _, err := b.client.DeleteSnapshot(ctx, input); err != nil {
		return resource.Accepted[resource.Snapshot]{}, awsError(err)
	}
	return accepted(m, req.Action(), resource.KindSnapshot, []resource.Snapshot{{ID: req.ID, OwnerID: m.Account}})
}
