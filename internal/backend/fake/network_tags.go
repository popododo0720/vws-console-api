package fake

import (
	"context"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TagVpcs merges tags into each VPC. Every VPC must exist before any changes.
func (n network) TagVpcs(ctx context.Context, m backend.Mutation, req resource.TagVpcsRequest) (resource.Accepted[resource.Vpc], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Vpc]](n.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	merged := make([]map[string]string, 0, len(req.IDs))
	targets := make([]resource.Ref, 0, len(req.IDs))
	for _, id := range req.IDs {
		vpc, ok := n.w.vpc[id]
		if !ok || vpc.OwnerID != m.Account {
			return resource.Accepted[resource.Vpc]{}, resource.NotFound(resource.KindVpc, id.String())
		}
		tags, err := resource.MergeTags(vpc.Tags, req.Tags)
		if err != nil {
			return resource.Accepted[resource.Vpc]{}, err
		}
		merged = append(merged, tags)
		targets = append(targets, id.Ref())
	}
	op, err := n.w.newOp(m.Account, resource.ServiceNetwork, resource.ActionCreateTags, targets, func(time.Time) {})
	if err != nil {
		return resource.Accepted[resource.Vpc]{}, err
	}
	items := make([]resource.Vpc, 0, len(req.IDs))
	for i, id := range req.IDs {
		vpc := n.w.vpc[id]
		vpc.Tags = merged[i]
		item := *vpc
		item.Tags = copyTags(vpc.Tags)
		items = append(items, item)
	}
	acc := resource.Accepted[resource.Vpc]{Operation: op, Items: items}
	n.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

// TagSubnets merges tags into each subnet. Every subnet must exist before any
// changes.
func (n network) TagSubnets(ctx context.Context, m backend.Mutation, req resource.TagSubnetsRequest) (resource.Accepted[resource.Subnet], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	n.w.mu.Lock()
	defer n.w.mu.Unlock()
	n.w.settle(n.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Subnet]](n.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	merged := make([]map[string]string, 0, len(req.IDs))
	targets := make([]resource.Ref, 0, len(req.IDs))
	for _, id := range req.IDs {
		sub, ok := n.w.sub[id]
		if !ok || sub.OwnerID != m.Account {
			return resource.Accepted[resource.Subnet]{}, resource.NotFound(resource.KindSubnet, id.String())
		}
		tags, err := resource.MergeTags(sub.Tags, req.Tags)
		if err != nil {
			return resource.Accepted[resource.Subnet]{}, err
		}
		merged = append(merged, tags)
		targets = append(targets, id.Ref())
	}
	op, err := n.w.newOp(m.Account, resource.ServiceNetwork, resource.ActionCreateTags, targets, func(time.Time) {})
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	items := make([]resource.Subnet, 0, len(req.IDs))
	for i, id := range req.IDs {
		sub := n.w.sub[id]
		sub.Tags = merged[i]
		item := *sub
		item.Tags = copyTags(sub.Tags)
		items = append(items, item)
	}
	acc := resource.Accepted[resource.Subnet]{Operation: op, Items: items}
	n.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}
