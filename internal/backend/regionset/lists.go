package regionset

import (
	"context"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type compute struct {
	backend.Compute
	r *router
}

type network struct {
	backend.Network
	r *router
}

type storage struct {
	backend.Storage
	r *router
}

func (c compute) DescribeInstances(ctx context.Context, s backend.Scope,
	q resource.InstanceQuery,
) (resource.Page[resource.Instance], error) {
	return list[resource.Instance](ctx, c.r, s, q.Page, func(p resource.PageRequest) any {
		req := q
		req.Page = p
		return req
	}, "Compute", "DescribeInstances")
}

func (c compute) DescribeVolumes(ctx context.Context, s backend.Scope,
	q resource.VolumeQuery,
) (resource.Page[resource.Volume], error) {
	return list[resource.Volume](ctx, c.r, s, q.Page, func(p resource.PageRequest) any {
		req := q
		req.Page = p
		return req
	}, "Compute", "DescribeVolumes")
}

func (c compute) DescribeSnapshots(ctx context.Context, s backend.Scope,
	q resource.SnapshotQuery,
) (resource.Page[resource.Snapshot], error) {
	return list[resource.Snapshot](ctx, c.r, s, q.Page, func(p resource.PageRequest) any {
		req := q
		req.Page = p
		return req
	}, "Compute", "DescribeSnapshots")
}

func (c compute) DescribeImages(ctx context.Context, s backend.Scope,
	q resource.ImageQuery,
) (resource.Page[resource.Image], error) {
	return list[resource.Image](ctx, c.r, s, q.Page, func(p resource.PageRequest) any {
		req := q
		req.Page = p
		return req
	}, "Compute", "DescribeImages")
}

func (c compute) DescribeKeyPairs(ctx context.Context, s backend.Scope,
	q resource.KeyPairQuery,
) (resource.Page[resource.KeyPair], error) {
	return list[resource.KeyPair](ctx, c.r, s, q.Page, func(p resource.PageRequest) any {
		req := q
		req.Page = p
		return req
	}, "Compute", "DescribeKeyPairs")
}

func (n network) DescribeVpcs(ctx context.Context, s backend.Scope,
	q resource.VpcQuery,
) (resource.Page[resource.Vpc], error) {
	return list[resource.Vpc](ctx, n.r, s, q.Page, func(p resource.PageRequest) any {
		req := q
		req.Page = p
		return req
	}, "Network", "DescribeVpcs")
}

func (n network) DescribeSubnets(ctx context.Context, s backend.Scope,
	q resource.SubnetQuery,
) (resource.Page[resource.Subnet], error) {
	return list[resource.Subnet](ctx, n.r, s, q.Page, func(p resource.PageRequest) any {
		req := q
		req.Page = p
		return req
	}, "Network", "DescribeSubnets")
}

func (n network) DescribeSecurityGroups(ctx context.Context, s backend.Scope,
	q resource.SecurityGroupQuery,
) (resource.Page[resource.SecurityGroup], error) {
	return list[resource.SecurityGroup](ctx, n.r, s, q.Page, func(p resource.PageRequest) any {
		req := q
		req.Page = p
		return req
	}, "Network", "DescribeSecurityGroups")
}

func (n network) DescribeAddresses(ctx context.Context, s backend.Scope,
	q resource.AddressQuery,
) (resource.Page[resource.Address], error) {
	return list[resource.Address](ctx, n.r, s, q.Page, func(p resource.PageRequest) any {
		req := q
		req.Page = p
		return req
	}, "Network", "DescribeAddresses")
}

func (s storage) ListBuckets(ctx context.Context, scope backend.Scope,
	q resource.BucketQuery,
) (resource.Page[resource.Bucket], error) {
	return list[resource.Bucket](ctx, s.r, scope, q.Page, func(p resource.PageRequest) any {
		req := q
		req.Page = p
		return req
	}, "Storage", "ListBuckets")
}
