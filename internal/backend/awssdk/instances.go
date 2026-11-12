package awssdk

import (
	"cmp"
	"context"
	"encoding"
	"fmt"
	"log/slog"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// DescribeInstances reads every upstream page before applying the model's page size.
// EC2's minimum MaxResults is five, while the model permits a page of one.
func (b *Backend) DescribeInstances(
	ctx context.Context, s backend.Scope, q resource.InstanceQuery,
) (resource.Page[resource.Instance], error) {
	if s.Region != b.region {
		return resource.Page[resource.Instance]{}, resource.Invalid("region", "not served by this backend")
	}
	q, err := q.Normalize()
	if err != nil {
		return resource.Page[resource.Instance]{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	input := &ec2.DescribeInstancesInput{}
	for _, id := range q.IDs {
		input.InstanceIds = append(input.InstanceIds, id.String())
	}
	if len(q.States) != 0 {
		filter := types.Filter{Name: aws.String("instance-state-name")}
		for _, state := range q.States {
			filter.Values = append(filter.Values, state.String())
		}
		input.Filters = append(input.Filters, filter)
	}
	pages := ec2.NewDescribeInstancesPaginator(b.client, input)
	var rows []resource.Instance
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return resource.Page[resource.Instance]{}, awsError(err)
		}
		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				mapped, err := mapInstance(instance, reservation.ReservationId)
				if err != nil {
					if len(q.IDs) != 0 {
						return resource.Page[resource.Instance]{}, resource.Internal(err)
					}
					slog.WarnContext(ctx, "skipping invalid AWS instance",
						slog.String("id", aws.ToString(instance.InstanceId)), slog.Any("error", err))
					continue
				}
				mapped.OwnerID = s.Account
				rows = append(rows, mapped)
			}
		}
	}
	slices.SortFunc(rows, func(a, b resource.Instance) int {
		return cmp.Compare(a.ID.String(), b.ID.String())
	})
	start := 0
	if q.Page.Token != "" {
		index := slices.IndexFunc(rows, func(i resource.Instance) bool { return i.ID.String() == q.Page.Token })
		if index < 0 {
			return resource.Page[resource.Instance]{}, resource.Invalid("pageToken", "unknown")
		}
		start = index + 1
	}
	end := min(start+q.Page.Size, len(rows))
	result := resource.Page[resource.Instance]{Items: rows[start:end]}
	if end < len(rows) {
		result.NextToken = rows[end-1].ID.String()
	}
	return result, nil
}

func mapInstance(i types.Instance, reservation *string) (resource.Instance, error) {
	out := resource.Instance{
		InstanceType: string(i.InstanceType), KeyName: aws.ToString(i.KeyName),
		PrivateIP: aws.ToString(i.PrivateIpAddress), PublicIP: aws.ToString(i.PublicIpAddress),
		LaunchTime: aws.ToTime(i.LaunchTime), RootDeviceName: aws.ToString(i.RootDeviceName),
		Tags: make(map[string]string),
	}
	ids := []struct {
		target encoding.TextUnmarshaler
		value  *string
	}{
		{&out.ID, i.InstanceId},
		{&out.ReservationID, reservation},
		{&out.ImageID, i.ImageId},
		{&out.SubnetID, i.SubnetId},
		{&out.VpcID, i.VpcId},
	}
	for _, id := range ids {
		if id.value != nil {
			if err := id.target.UnmarshalText([]byte(*id.value)); err != nil {
				return resource.Instance{}, fmt.Errorf("awssdk: instance identifier: %w", err)
			}
		}
	}
	if out.ID.IsZero() || out.ImageID.IsZero() || out.ReservationID.IsZero() || i.State == nil {
		return resource.Instance{}, resource.Invalid("instance", "missing required AWS inventory field")
	}
	state, ok := resource.ParseInstanceState(string(i.State.Name))
	if !ok {
		return resource.Instance{}, resource.Invalid("state", "unknown AWS instance state")
	}
	out.State = state
	if i.StateReason != nil {
		out.StateReason = resource.StateReason{
			Code: aws.ToString(i.StateReason.Code), Message: aws.ToString(i.StateReason.Message),
		}
	}
	if i.Placement != nil {
		out.Zone = aws.ToString(i.Placement.AvailabilityZone)
	}
	for _, tag := range i.Tags {
		out.Tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	for _, nic := range i.NetworkInterfaces {
		subnet, err := resource.Parse[resource.SubnetID](aws.ToString(nic.SubnetId))
		if err != nil {
			return resource.Instance{}, fmt.Errorf("awssdk: interface subnet: %w", err)
		}
		vpc, err := resource.Parse[resource.VpcID](aws.ToString(nic.VpcId))
		if err != nil {
			return resource.Instance{}, fmt.Errorf("awssdk: interface VPC: %w", err)
		}
		index := 0
		if nic.Attachment != nil {
			index = int(aws.ToInt32(nic.Attachment.DeviceIndex))
		}
		out.NetworkInterfaces = append(out.NetworkInterfaces, resource.NetworkInterface{
			DeviceIndex: index, SubnetID: subnet, VpcID: vpc, PrivateIP: aws.ToString(nic.PrivateIpAddress),
		})
	}
	if len(out.NetworkInterfaces) > 0 {
		out.SetInterfaces(out.NetworkInterfaces)
	}
	for _, device := range i.BlockDeviceMappings {
		if device.Ebs == nil {
			continue
		}
		id, err := resource.Parse[resource.VolumeID](aws.ToString(device.Ebs.VolumeId))
		if err != nil {
			return resource.Instance{}, fmt.Errorf("awssdk: block device identifier: %w", err)
		}
		out.BlockDevices = append(out.BlockDevices, resource.BlockDevice{
			Device: aws.ToString(device.DeviceName), VolumeID: id,
			DeleteOnTermination: aws.ToBool(device.Ebs.DeleteOnTermination),
			Status:              resource.AttachmentStatus(device.Ebs.Status), AttachTime: aws.ToTime(device.Ebs.AttachTime),
		})
	}
	return out, nil
}
