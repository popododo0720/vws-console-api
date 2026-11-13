package main

import (
	"context"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func testRegionConnection(
	ctx context.Context, registry *store.Registry, region store.Region, token string,
) []resource.ConnectionStep {
	projects, skipped, err := registry.Projects().List(ctx)
	if err != nil || len(skipped) != 0 {
		var steps []resource.ConnectionStep
		for _, name := range []string{"tls", "version", "cluster_name", "privileges"} {
			steps = append(steps, resource.ConnectionStep{
				Name: name, Result: resource.ConnectionSkipped, Message: "managed project pools could not be read",
			})
		}
		steps[3].Result = resource.ConnectionFail
		return steps
	}
	var pools []string
	for _, project := range projects {
		for _, binding := range project.Pools {
			if binding.Region == region.Name {
				pools = append(pools, binding.Pool)
			}
		}
	}
	return proxmox.TestConnection(ctx, proxmox.ConnectionConfig{
		URL: region.PVEAPIURL, CAPEM: region.CAPEM, ClusterName: region.ClusterName,
		TokenID: region.TokenID, TokenSecret: token, Pools: pools,
	})
}
