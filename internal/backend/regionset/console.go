package regionset

import (
	"context"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (r *router) OpenConsole(
	ctx context.Context, scope backend.Scope, id resource.InstanceID, kind resource.ConsoleKind,
) (resource.ConsoleSession, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	regions, err := r.regions(ctx)
	if err != nil {
		return resource.ConsoleSession{}, err
	}
	for _, region := range regions {
		if region.Name != scope.Region || scope.Region == "all" {
			continue
		}
		transport, err := r.resolve(ctx, region)
		if err != nil {
			return resource.ConsoleSession{}, regionalError(err)
		}
		console, ok := transport.(backend.Console)
		if !ok {
			return resource.ConsoleSession{}, resource.Unsupported("OpenConsole", "console transport unavailable")
		}
		session, err := console.OpenConsole(ctx, scope, id, kind)
		return session, regionalError(err)
	}
	return resource.ConsoleSession{}, resource.Invalid("region", "a registered region is required")
}
