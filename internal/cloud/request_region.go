package cloud

import (
	"context"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// RequestRegion selects a registered region before any inventory call.
func (s *Service) RequestRegion(ctx context.Context, c resource.Caller, name string) (resource.Caller, error) {
	if name == "" {
		return c, nil
	}
	if len(name) > 63 || strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
		return c, resource.Invalid("region", "invalid region name")
	}
	if name != "all" {
		found, err := backend.HasRegion(ctx, s.regions, name)
		if err != nil {
			return c, &resource.Error{Code: resource.CodeUnavailable, Message: "region catalog unavailable"}
		}
		if !found {
			return c, resource.Invalid("region", "a registered region is required")
		}
	}
	c.Region = name
	return c, nil
}
