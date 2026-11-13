package proxmox

import (
	"context"
	"fmt"
	"slices"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func checkPools(ctx context.Context, client *pveclient.Client, pools []string) error {
	pools = slices.Sorted(slices.Values(pools))
	for _, pool := range slices.Compact(pools) {
		path := "/pool/" + pool
		permissions, err := client.AccessPermissions(ctx, path)
		if err != nil {
			return (&resource.Error{
				Code: resource.CodeUnavailable, Message: fmt.Sprintf("pool %q: privileges could not be verified", pool),
			}).WithCause(err)
		}
		for _, privilege := range []string{"Pool.Audit", "VM.Audit"} {
			if _, ok := permissions[path][privilege]; !ok {
				return &resource.Error{
					Code: resource.CodeUnavailable, Message: fmt.Sprintf("pool %q: missing %s", pool, privilege),
				}
			}
		}
		exists, err := client.Pool(ctx, pool)
		if err != nil {
			return (&resource.Error{
				Code: resource.CodeUnavailable, Message: fmt.Sprintf("pool %q: existence could not be verified", pool),
			}).WithCause(err)
		}
		if !exists {
			return &resource.Error{Code: resource.CodeUnavailable, Message: fmt.Sprintf("pool %q: does not exist", pool)}
		}
	}
	return nil
}
