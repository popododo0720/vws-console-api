package grpcclient

import (
	"bytes"
	"context"
	"io"

	"github.com/popododo0720/vws-console-api/internal/backend"
	commonv1 "github.com/popododo0720/vws-console-api/internal/backend/grpcclient/internal/pb/commonv1"
	computev1 "github.com/popododo0720/vws-console-api/internal/backend/grpcclient/internal/pb/computev1"
	networkv1 "github.com/popododo0720/vws-console-api/internal/backend/grpcclient/internal/pb/networkv1"
	storagev1 "github.com/popododo0720/vws-console-api/internal/backend/grpcclient/internal/pb/storagev1"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type computeClient struct{ api computev1.ComputeClient }

func (c computeClient) RunInstances(ctx context.Context, m backend.Mutation, req resource.RunInstancesRequest) (resource.Accepted[resource.Instance], error) {
	out, err := c.api.RunInstances(ctx, &computev1.RunInstancesRequest{
		Mutation: mutationProto(m), ImageId: req.ImageID.String(), InstanceType: req.InstanceType,
		SubnetId: req.SubnetID.String(), Count: int32(req.Count), Tags: req.Tags,
	})
	if err != nil {
		return resource.Accepted[resource.Instance]{}, fromRPC(err)
	}
	op, err := operationModel(out.GetOperation())
	if err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	items := make([]resource.Instance, 0, len(out.GetInstances()))
	for _, item := range out.GetInstances() {
		inst, err := instanceModel(item)
		if err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
		items = append(items, inst)
	}
	return resource.Accepted[resource.Instance]{Operation: op, Items: items}, nil
}

func (c computeClient) StopInstances(ctx context.Context, m backend.Mutation, req resource.StopInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	ids := make([]string, 0, len(req.IDs))
	for _, id := range req.IDs {
		ids = append(ids, id.String())
	}
	out, err := c.api.StopInstances(ctx, &computev1.StopInstancesRequest{Mutation: mutationProto(m), InstanceIds: ids})
	if err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, fromRPC(err)
	}
	op, err := operationModel(out.GetOperation())
	if err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	items := make([]resource.InstanceStateChange, 0, len(out.GetChanges()))
	for _, ch := range out.GetChanges() {
		id, err := resource.Parse[resource.InstanceID](ch.GetInstanceId())
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, resource.Internal(err)
		}
		owner, err := resource.Parse[resource.AccountID](ch.GetOwnerId())
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, resource.Internal(err)
		}
		prev, ok := resource.ParseInstanceState(ch.GetPreviousState())
		cur, ok2 := resource.ParseInstanceState(ch.GetCurrentState())
		if !ok || !ok2 {
			return resource.Accepted[resource.InstanceStateChange]{}, resource.Internal(errString("bad instance state"))
		}
		items = append(items, resource.InstanceStateChange{ID: id, OwnerID: owner, Previous: prev, Current: cur})
	}
	return resource.Accepted[resource.InstanceStateChange]{Operation: op, Items: items}, nil
}

func (c computeClient) DescribeInstances(ctx context.Context, s backend.Scope, q resource.InstanceQuery) (resource.Page[resource.Instance], error) {
	ids := make([]string, 0, len(q.IDs))
	for _, id := range q.IDs {
		ids = append(ids, id.String())
	}
	states := make([]string, 0, len(q.States))
	for _, st := range q.States {
		states = append(states, st.String())
	}
	out, err := c.api.DescribeInstances(ctx, &computev1.DescribeInstancesRequest{
		Scope: scopeProto(s), InstanceIds: ids, States: states, Page: pageProto(q.Page),
	})
	if err != nil {
		return resource.Page[resource.Instance]{}, fromRPC(err)
	}
	items := make([]resource.Instance, 0, len(out.GetInstances()))
	for _, item := range out.GetInstances() {
		inst, err := instanceModel(item)
		if err != nil {
			return resource.Page[resource.Instance]{}, err
		}
		items = append(items, inst)
	}
	return resource.Page[resource.Instance]{Items: items, NextToken: out.GetNextPageToken()}, nil
}

func (c computeClient) GetOperation(ctx context.Context, s backend.Scope, id resource.OperationID) (resource.Operation, error) {
	out, err := c.api.GetOperation(ctx, &commonv1.GetOperationRequest{Scope: scopeProto(s), OperationId: id.String()})
	if err != nil {
		return resource.Operation{}, fromRPC(err)
	}
	return operationModel(out)
}

type storageClient struct{ api storagev1.StorageClient }

func (c storageClient) CreateBucket(ctx context.Context, s backend.Scope, name resource.BucketName) (resource.Bucket, error) {
	out, err := c.api.CreateBucket(ctx, &storagev1.CreateBucketRequest{Scope: scopeProto(s), Name: name.String()})
	if err != nil {
		return resource.Bucket{}, fromRPC(err)
	}
	return bucketModel(out)
}

func (c storageClient) GetBucket(ctx context.Context, s backend.Scope, name resource.BucketName) (resource.Bucket, error) {
	out, err := c.api.GetBucket(ctx, &storagev1.GetBucketRequest{Scope: scopeProto(s), Name: name.String()})
	if err != nil {
		return resource.Bucket{}, fromRPC(err)
	}
	return bucketModel(out)
}

func (c storageClient) ListBuckets(ctx context.Context, s backend.Scope, q resource.BucketQuery) (resource.Page[resource.Bucket], error) {
	out, err := c.api.ListBuckets(ctx, &storagev1.ListBucketsRequest{Scope: scopeProto(s), Page: pageProto(q.Page)})
	if err != nil {
		return resource.Page[resource.Bucket]{}, fromRPC(err)
	}
	items := make([]resource.Bucket, 0, len(out.GetBuckets()))
	for _, item := range out.GetBuckets() {
		b, err := bucketModel(item)
		if err != nil {
			return resource.Page[resource.Bucket]{}, err
		}
		items = append(items, b)
	}
	return resource.Page[resource.Bucket]{Items: items, NextToken: out.GetNextPageToken()}, nil
}

func (c storageClient) DeleteBucket(ctx context.Context, s backend.Scope, name resource.BucketName) error {
	_, err := c.api.DeleteBucket(ctx, &storagev1.DeleteBucketRequest{Scope: scopeProto(s), Name: name.String()})
	return fromRPC(err)
}

func (c storageClient) PutObject(ctx context.Context, s backend.Scope, req resource.PutObjectRequest, body io.Reader) (resource.Object, error) {
	buf, err := io.ReadAll(io.LimitReader(body, resource.MaxObjectBytes+1))
	if err != nil {
		return resource.Object{}, resource.Internal(err)
	}
	if len(buf) > resource.MaxObjectBytes {
		return resource.Object{}, resource.Exhausted("object exceeds 5 MiB")
	}
	out, err := c.api.PutObject(ctx, &storagev1.PutObjectRequest{
		Scope: scopeProto(s), Bucket: req.Bucket.String(), Key: req.Key.String(), ContentType: req.ContentType, Body: buf,
	})
	if err != nil {
		return resource.Object{}, fromRPC(err)
	}
	return objectModel(out)
}

func (c storageClient) GetObject(ctx context.Context, s backend.Scope, req resource.GetObjectRequest) (resource.Object, io.ReadCloser, error) {
	out, err := c.api.GetObject(ctx, &storagev1.GetObjectRequest{Scope: scopeProto(s), Bucket: req.Bucket.String(), Key: req.Key.String()})
	if err != nil {
		return resource.Object{}, nil, fromRPC(err)
	}
	meta, err := objectModel(out.GetObject())
	if err != nil {
		return resource.Object{}, nil, err
	}
	return meta, io.NopCloser(bytes.NewReader(out.GetBody())), nil
}

func (c storageClient) DeleteObject(ctx context.Context, s backend.Scope, bucket resource.BucketName, key resource.ObjectKey) error {
	_, err := c.api.DeleteObject(ctx, &storagev1.DeleteObjectRequest{Scope: scopeProto(s), Bucket: bucket.String(), Key: key.String()})
	return fromRPC(err)
}

type networkClient struct{ api networkv1.NetworkClient }

func (c networkClient) CreateSubnet(ctx context.Context, m backend.Mutation, req resource.CreateSubnetRequest) (resource.Accepted[resource.Subnet], error) {
	out, err := c.api.CreateSubnet(ctx, &networkv1.CreateSubnetRequest{Mutation: mutationProto(m), CidrBlock: req.Cidr})
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, fromRPC(err)
	}
	op, err := operationModel(out.GetOperation())
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	items := make([]resource.Subnet, 0, len(out.GetSubnets()))
	for _, item := range out.GetSubnets() {
		sub, err := subnetModel(item)
		if err != nil {
			return resource.Accepted[resource.Subnet]{}, err
		}
		items = append(items, sub)
	}
	return resource.Accepted[resource.Subnet]{Operation: op, Items: items}, nil
}

func (c networkClient) DescribeSubnets(ctx context.Context, s backend.Scope, q resource.SubnetQuery) (resource.Page[resource.Subnet], error) {
	ids := make([]string, 0, len(q.IDs))
	for _, id := range q.IDs {
		ids = append(ids, id.String())
	}
	out, err := c.api.DescribeSubnets(ctx, &networkv1.DescribeSubnetsRequest{Scope: scopeProto(s), SubnetIds: ids, Page: pageProto(q.Page)})
	if err != nil {
		return resource.Page[resource.Subnet]{}, fromRPC(err)
	}
	items := make([]resource.Subnet, 0, len(out.GetSubnets()))
	for _, item := range out.GetSubnets() {
		sub, err := subnetModel(item)
		if err != nil {
			return resource.Page[resource.Subnet]{}, err
		}
		items = append(items, sub)
	}
	return resource.Page[resource.Subnet]{Items: items, NextToken: out.GetNextPageToken()}, nil
}

func (c networkClient) GetOperation(ctx context.Context, s backend.Scope, id resource.OperationID) (resource.Operation, error) {
	out, err := c.api.GetOperation(ctx, &commonv1.GetOperationRequest{Scope: scopeProto(s), OperationId: id.String()})
	if err != nil {
		return resource.Operation{}, fromRPC(err)
	}
	return operationModel(out)
}
