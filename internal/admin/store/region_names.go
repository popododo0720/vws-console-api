package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// ClaimGrace is how long a claim whose owner does not hold the cluster stays
// reserved. It covers the window in which the owner writes or renames its
// region record after claiming, well past the registry's per-call deadline.
const ClaimGrace = 2 * time.Minute

// ErrInvalidClaim reports a cluster or region name a claim key cannot hold.
var ErrInvalidClaim = errors.New("invalid cluster claim")

var claimName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

type clusterClaim struct {
	Region    string    `json:"region"`
	ClaimedAt time.Time `json:"claimedAt"`
}

// ClaimCluster reserves a cluster name for a region using the registry CAS.
// A region may claim again what it already holds. Another region's claim is
// taken over only when its owner does not hold the cluster and the claim is
// older than ClaimGrace, so a claim whose record is still being written stays.
func (g *Registry) ClaimCluster(ctx context.Context, cluster, region string, now time.Time) error {
	value, err := json.Marshal(clusterClaim{Region: region, ClaimedAt: now.UTC()})
	if err != nil {
		return fmt.Errorf("encode cluster claim: %w", err)
	}
	entry, held, err := g.readClaim(ctx, cluster, region)
	switch {
	case errors.Is(err, ErrNotFound):
		if _, err := g.b.Create(ctx, "cluster-names/"+cluster, value); err != nil {
			return fmt.Errorf("claim cluster: %w", err)
		}
		return nil
	case err != nil:
		return err
	case held.Region == region:
		return nil
	}
	owner, err := g.Regions().Get(ctx, held.Region)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("read cluster owner: %w", err)
	}
	if err == nil && owner.ClusterName == cluster || now.Sub(held.ClaimedAt) < ClaimGrace {
		return ErrExists
	}
	if _, err := g.b.Update(ctx, "cluster-names/"+cluster, value, entry.Version); err != nil {
		return fmt.Errorf("reclaim cluster: %w", err)
	}
	return nil
}

// ReleaseCluster removes only the claim owned by region.
func (g *Registry) ReleaseCluster(ctx context.Context, cluster, region string) error {
	entry, held, err := g.readClaim(ctx, cluster, region)
	if errors.Is(err, ErrNotFound) || err == nil && held.Region != region {
		return nil
	}
	if err != nil {
		return err
	}
	if err := g.b.Delete(ctx, "cluster-names/"+cluster, entry.Version); err != nil {
		return fmt.Errorf("release cluster: %w", err)
	}
	return nil
}

func (g *Registry) readClaim(ctx context.Context, cluster, region string) (Entry, clusterClaim, error) {
	var held clusterClaim
	if !claimName.MatchString(cluster) || !claimName.MatchString(region) {
		return Entry{}, held, ErrInvalidClaim
	}
	entry, err := g.b.Get(ctx, "cluster-names/"+cluster)
	if err != nil {
		return Entry{}, held, fmt.Errorf("read cluster claim: %w", err)
	}
	if err := json.Unmarshal(entry.Value, &held); err != nil || held.Region == "" {
		return Entry{}, held, errors.Join(errors.New("undecodable cluster claim"), err)
	}
	return entry, held, nil
}
