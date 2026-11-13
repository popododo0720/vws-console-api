package cloud

import (
	"context"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// GetAllocation returns current provisioned capacity in one region.
func (s *Service) GetAllocation(ctx context.Context, c resource.Caller) (resource.Allocation, error) {
	if c.Account.IsZero() {
		return resource.Allocation{}, resource.Unauthenticated("account is required")
	}
	if s.backends.Usage == nil {
		return resource.Allocation{}, resource.Unsupported("GetAllocation", "allocation is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.backends.Usage.GetAllocation(ctx, scope(c), struct{}{})
}
