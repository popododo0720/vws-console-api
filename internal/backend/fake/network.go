package fake

import (
	"context"
	"errors"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type network struct{ w *World }

func (n network) CreateSubnet(ctx context.Context, m backend.Mutation, req resource.CreateSubnetRequest) (resource.Accepted[resource.Subnet], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	if hit, ok, err := n.w.begin(m.Key, m.Fingerprint); err != nil || ok {
		if err != nil {
			return resource.Accepted[resource.Subnet]{}, err
		}
		acc, _ := hit.(resource.Accepted[resource.Subnet])
		if len(acc.Items) == 0 || n.w.sub[acc.Items[0].ID] != nil {
			return acc, nil
		}
	}
	id, err := resource.Mint[resource.SubnetID](n.w.entropy)
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	if _, exists := n.w.sub[id]; exists {
		return resource.Accepted[resource.Subnet]{}, resource.Internal(errors.New("identifier collision"))
	}
	if !req.VpcID.IsZero() {
		vpc, ok := n.w.vpc[req.VpcID]
		if !ok || vpc.OwnerID != m.Account {
			return resource.Accepted[resource.Subnet]{}, resource.NotFound(resource.KindVpc, req.VpcID.String())
		}
		if vpc.State != resource.VpcAvailable {
			return resource.Accepted[resource.Subnet]{}, resource.Conflict(resource.KindVpc, req.VpcID.String(), "vpc is not available")
		}
		if !cidrInside(req.Cidr, vpc.Cidr) {
			return resource.Accepted[resource.Subnet]{}, resource.Invalid("cidrBlock", "must be inside the vpc")
		}
	}
	sub := resource.Subnet{
		ID:      id,
		OwnerID: m.Account,
		VpcID:   req.VpcID,
		Cidr:    req.Cidr,
		State:   resource.SubnetPending,
	}
	op, err := n.w.newOp(m.Account, resource.ServiceNetwork, resource.ActionCreateSubnet, []resource.Ref{id.Ref()}, func(time.Time) {
		if cur := n.w.sub[id]; cur != nil && cur.State == resource.SubnetPending {
			cur.State = resource.SubnetAvailable
		}
	})
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	stored := sub
	n.w.sub[id] = &stored
	acc := resource.Accepted[resource.Subnet]{Operation: op, Items: []resource.Subnet{sub}}
	n.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (n network) DescribeSubnets(ctx context.Context, s backend.Scope, q resource.SubnetQuery) (resource.Page[resource.Subnet], error) {
	if err := ctx.Err(); err != nil {
		return resource.Page[resource.Subnet]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	want := map[resource.SubnetID]struct{}{}
	for _, id := range q.IDs {
		want[id] = struct{}{}
	}
	var items []resource.Subnet
	for _, sub := range n.w.sub {
		if sub.OwnerID != s.Account {
			continue
		}
		if len(want) > 0 {
			if _, ok := want[sub.ID]; !ok {
				continue
			}
		}
		items = append(items, *sub)
	}
	sortSubnets(items)
	if len(q.IDs) == 1 && len(items) == 0 {
		return resource.Page[resource.Subnet]{}, resource.NotFound(resource.KindSubnet, q.IDs[0].String())
	}
	return page(items, q.Page)
}

func (n network) GetOperation(ctx context.Context, s backend.Scope, id resource.OperationID) (resource.Operation, error) {
	if err := ctx.Err(); err != nil {
		return resource.Operation{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	return n.w.getOp(s, id, resource.ServiceNetwork)
}

func sortSubnets(items []resource.Subnet) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].ID.String() < items[j-1].ID.String(); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}
