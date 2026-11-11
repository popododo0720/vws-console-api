package cloud

import (
	"context"
	"fmt"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// admit refuses a mutation the region does not serve, before the backend
// sees it. Until Scope carries a region the kernel serves resource.RegionName.
func (s *Service) admit(ctx context.Context, a resource.Action) error {
	caps, err := s.caps.RegionCapabilities(ctx, resource.RegionName)
	if err != nil {
		return fmt.Errorf("capabilities of %s: %w", resource.RegionName, err)
	}
	got := caps.Mutation(a)
	switch got.State {
	case resource.ActionSupported, resource.ActionPartial:
		return nil
	case resource.ActionUnsupported, resource.ActionEmpty:
	}
	message := fmt.Sprintf("%s is not supported in region %s", a, resource.RegionName)
	if got.Reason != "" {
		message += ": " + got.Reason
	}
	return resource.Unsupported("Action", message)
}

// served answers a read the region does not serve with an empty page, so a
// client that lists everything, as Terraform does, still succeeds.
func served[Q any, T any](
	s *Service,
	read resource.ReadAction,
	call func(context.Context, backend.Scope, Q) (resource.Page[T], error),
) func(context.Context, backend.Scope, Q) (resource.Page[T], error) {
	return func(ctx context.Context, sc backend.Scope, q Q) (resource.Page[T], error) {
		caps, err := s.caps.RegionCapabilities(ctx, resource.RegionName)
		if err != nil {
			return resource.Page[T]{}, fmt.Errorf("capabilities of %s: %w", resource.RegionName, err)
		}
		switch caps.Read(read).State {
		case resource.ActionSupported, resource.ActionPartial:
			return call(ctx, sc, q)
		case resource.ActionEmpty, resource.ActionUnsupported:
		}
		return resource.Page[T]{}, nil
	}
}
