package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Project maps a VWS project to its Proxmox pools and registered AWS accounts.
type Project struct {
	Project     string        `json:"project"`
	Pools       []ProjectPool `json:"pools"`
	AWSAccounts []string      `json:"awsAccounts"`
	Version     Version       `json:"-"`
}

// ProjectPool is the project's pool in one registered region.
type ProjectPool struct {
	Region string `json:"region"`
	Pool   string `json:"pool"`
}

func (p *Project) name() string         { return p.Project }
func (p *Project) version() Version     { return p.Version }
func (p *Project) setVersion(v Version) { p.Version = v }

// Projects reads mappings and writes each mapping together with its exclusive claims.
func (g *Registry) Projects() Projects {
	return Projects{records: Collection[Project, *Project]{b: g.b, kind: "projects/"}}
}

// Projects is the CAS collection of project mappings.
type Projects struct{ records Collection[Project, *Project] }

// Get reads a stored mapping; ErrNotFound means the caller may use default pools.
func (p Projects) Get(ctx context.Context, project string) (Project, error) {
	return p.records.Get(ctx, project)
}

// List reads stored mappings in project order and reports undecodable records.
func (p Projects) List(ctx context.Context) ([]Project, []Undecodable, error) {
	items, skipped, err := p.records.List(ctx)
	for i := range items {
		items[i].Pools = append([]ProjectPool{}, items[i].Pools...)
		items[i].AWSAccounts = append([]string{}, items[i].AWSAccounts...)
	}
	return items, skipped, err
}

// PoolConflictError identifies a pool held by another project.
type PoolConflictError struct{ Region, Pool string }

func (e *PoolConflictError) Error() string {
	return fmt.Sprintf("pool %s in region %s is already mapped", e.Pool, e.Region)
}

// Unwrap exposes the registry's duplicate-owner error.
func (*PoolConflictError) Unwrap() error { return ErrExists }

// ValidateProject checks names, duplicates and the size of one atomic mapping update.
func ValidateProject(v Project) error {
	account := regexp.MustCompile(`^[0-9]{12}$`)
	if !account.MatchString(v.Project) {
		return resource.Invalid("project", "must be 12 digits")
	}
	// At most 65 compares and 65 writes when every old pool is replaced,
	// below etcd's default 128-operation transaction limit.
	if len(v.Pools) > 32 || len(v.AWSAccounts) > 128 {
		return resource.Invalid("body", "at most 32 pools and 128 AWS accounts")
	}
	regions := map[string]bool{}
	for _, pool := range v.Pools {
		if len(pool.Region) > 63 ||
			!regexp.MustCompile(`^pve-[a-z0-9]+(-[a-z0-9]+)*-[0-9]+$`).MatchString(pool.Region) || regions[pool.Region] {
			return resource.Invalid("pools", "invalid or repeated region "+pool.Region)
		}
		if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`).MatchString(pool.Pool) {
			return resource.Invalid("pools", "invalid pool "+pool.Pool)
		}
		regions[pool.Region] = true
	}
	accounts := map[string]bool{}
	for _, id := range v.AWSAccounts {
		if !account.MatchString(id) || accounts[id] {
			return resource.Invalid("awsAccounts", "invalid or repeated AWS account "+id)
		}
		accounts[id] = true
	}
	return nil
}

// Put creates at version 0 or replaces at the version read, acquiring and releasing
// claims in the same CAS. A crash cannot leave a claim without its mapping.
func (p Projects) Put(ctx context.Context, v Project) (Project, error) {
	if err := ValidateProject(v); err != nil {
		return v, err
	}
	v.Pools = append([]ProjectPool{}, v.Pools...)
	v.AWSAccounts = append([]string{}, v.AWSAccounts...)
	slices.SortFunc(v.Pools, func(a, b ProjectPool) int { return strings.Compare(a.Region, b.Region) })
	slices.Sort(v.AWSAccounts)
	old, err := p.Get(ctx, v.Project)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	if old.Version != v.Version {
		return v, ErrConflict
	}
	if old.Version != 0 && slices.Equal(old.Pools, v.Pools) && slices.Equal(old.AWSAccounts, v.AWSAccounts) {
		return old, nil
	}
	key, data, err := p.records.encode(&v)
	if err != nil {
		return v, err
	}
	checks := []Entry{{Key: key, Version: v.Version}}
	puts := []Entry{{Key: key, Value: data}}
	var deletes []string
	seen := map[ProjectPool]bool{}
	for _, pool := range append(slices.Clone(v.Pools), old.Pools...) {
		if seen[pool] {
			continue
		}
		seen[pool] = true
		claimKey := "project-pools/" + pool.Region + "/" + pool.Pool
		entry, err := p.records.b.Get(ctx, claimKey)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return v, fmt.Errorf("read project pool claim: %w", err)
		}
		keep := slices.Contains(v.Pools, pool)
		if err == nil {
			var owner string
			if err := json.Unmarshal(entry.Value, &owner); err != nil {
				return v, fmt.Errorf("decode pool claim: %w", err)
			}
			if owner != v.Project {
				return v, &PoolConflictError{Region: pool.Region, Pool: pool.Pool}
			}
		} else if keep {
			value, err := json.Marshal(v.Project)
			if err != nil {
				return v, fmt.Errorf("encode pool owner: %w", err)
			}
			puts = append(puts, Entry{Key: claimKey, Value: value})
		}
		checks = append(checks, Entry{Key: claimKey, Version: entry.Version})
		if !keep && err == nil {
			deletes = append(deletes, claimKey)
		}
	}
	v.Version, err = p.records.b.Swap(ctx, checks, puts, deletes)
	if err != nil {
		return v, fmt.Errorf("save project mapping: %w", err)
	}
	return v, nil
}
