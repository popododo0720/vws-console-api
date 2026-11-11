package store

import (
	"context"
	"errors"
	"fmt"
)

// ClaimCluster reserves a cluster name for a region using the registry CAS.
func (g *Registry) ClaimCluster(ctx context.Context, cluster, region string) error {
	key := "cluster-names/" + cluster
	if _, err := g.b.Create(ctx, key, []byte(region)); err == nil {
		return nil
	} else if !errors.Is(err, ErrExists) {
		return fmt.Errorf("claim cluster: %w", err)
	}
	index, err := g.b.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("read cluster claim: %w", err)
	}
	owner, err := g.Regions().Get(ctx, string(index.Value))
	if err == nil && owner.ClusterName == cluster {
		return ErrExists
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("read cluster owner: %w", err)
	}
	if _, err := g.b.Update(ctx, key, []byte(region), index.Version); err != nil {
		return fmt.Errorf("reclaim cluster: %w", err)
	}
	return nil
}

// ReleaseCluster removes only the claim owned by region.
func (g *Registry) ReleaseCluster(ctx context.Context, cluster, region string) error {
	key := "cluster-names/" + cluster
	index, err := g.b.Get(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read cluster claim: %w", err)
	}
	if string(index.Value) != region {
		return nil
	}
	if err := g.b.Delete(ctx, key, index.Version); err != nil {
		return fmt.Errorf("release cluster: %w", err)
	}
	return nil
}
