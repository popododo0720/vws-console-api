package fake

import (
	"context"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TagVolumes merges tags into each volume. Every volume must exist before any
// changes.
func (c compute) TagVolumes(
	ctx context.Context, m backend.Mutation, req resource.TagVolumesRequest,
) (resource.Accepted[resource.Volume], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Volume]](c.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	merged := make([]map[string]string, 0, len(req.IDs))
	targets := make([]resource.Ref, 0, len(req.IDs))
	for _, id := range req.IDs {
		vol, ok := c.w.vol[id]
		if !ok || vol.OwnerID != m.Account {
			return resource.Accepted[resource.Volume]{}, resource.NotFound(resource.KindVolume, id.String())
		}
		tags, err := resource.MergeTags(vol.Tags, req.Tags)
		if err != nil {
			return resource.Accepted[resource.Volume]{}, err
		}
		merged = append(merged, tags)
		targets = append(targets, id.Ref())
	}
	op, err := c.w.newOp(m.Account, resource.ServiceCompute, resource.ActionCreateTags, targets, func(time.Time) {})
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	items := make([]resource.Volume, 0, len(req.IDs))
	for i, id := range req.IDs {
		vol := c.w.vol[id]
		// The map is replaced, never edited in place, so copies already
		// handed out keep the tags they had.
		vol.Tags = merged[i]
		item := *vol
		item.Tags = copyTags(vol.Tags)
		items = append(items, item)
	}
	acc := resource.Accepted[resource.Volume]{Operation: op, Items: items}
	c.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}
