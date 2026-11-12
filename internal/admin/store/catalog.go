package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type catalog struct{ registry *Registry }

// Catalog exposes registrations without their credentials to regional readers.
func (g *Registry) Catalog() backend.RegionCatalog { return catalog{g} }

func (c catalog) ProjectPool(ctx context.Context, project resource.AccountID, region string) (string, error) {
	mapping, err := c.registry.Projects().Get(ctx, project.String())
	if err != nil && !errors.Is(err, ErrNotFound) {
		return "", fmt.Errorf("project pool mapping: %w", err)
	}
	for _, binding := range mapping.Pools {
		if binding.Region == region {
			return binding.Pool, nil
		}
	}
	return project.String(), nil
}

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
