package proxmox

import (
	"context"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// PoolExists checks PVE without reading project mappings or changing membership.
func (b *Backend) PoolExists(ctx context.Context, pool string) (bool, error) {
	exists, err := b.client.Pool(ctx, pool)
	if err != nil {
		return false, (&resource.Error{
			Code: resource.CodeUnavailable, Message: "region pool check failed",
		}).WithCause(err)
	}
	return exists, nil
}
