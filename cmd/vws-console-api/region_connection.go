package main

import (
	"context"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func testRegionConnection(ctx context.Context, region store.Region, token string) []resource.ConnectionStep {
	return proxmox.TestConnection(ctx, proxmox.ConnectionConfig{
		URL: region.PVEAPIURL, CAPEM: region.CAPEM, ClusterName: region.ClusterName,
		TokenID: region.TokenID, TokenSecret: token,
	})
}
