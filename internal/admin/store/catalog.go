package store

import (
	"context"
	"fmt"

	"github.com/popododo0720/vws-console-api/internal/backend"
)

type catalog struct{ registry *Registry }

// Catalog exposes registrations without their credentials to regional readers.
func (g *Registry) Catalog() backend.RegionCatalog { return catalog{g} }

func (c catalog) ProxmoxRegions(ctx context.Context) ([]backend.ProxmoxRegion, error) {
	rows, _, err := c.registry.Regions().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("region catalog: %w", err)
	}
	out := make([]backend.ProxmoxRegion, len(rows))
	for i, row := range rows {
		out[i] = backend.ProxmoxRegion{Name: row.Name, Endpoint: row.RegionEndpoint}
		for _, zone := range row.Zones {
			out[i].Zones = append(out[i].Zones, backend.Zone{Letter: zone.Letter, Nodes: zone.Nodes})
		}
	}
	return out, nil
}

func (c catalog) AWSAccounts(ctx context.Context) ([]backend.AWSAccount, error) {
	rows, _, err := c.registry.AWSAccounts().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("AWS region catalog: %w", err)
	}
	out := make([]backend.AWSAccount, 0, len(rows))
	for _, row := range rows {
		out = append(out, backend.AWSAccount{ID: row.ID, AllowedRegions: row.AllowedRegions})
	}
	return out, nil
}
