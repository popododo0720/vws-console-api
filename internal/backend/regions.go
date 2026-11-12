package backend

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// RegionCatalog lists the regions this process routes. Operators register
// them through the admin API, so a caller reads the catalog on every use
// and a region added at runtime is served without a restart.
type RegionCatalog interface {
	ProxmoxRegions(ctx context.Context) ([]ProxmoxRegion, error)
	AWSAccounts(ctx context.Context) ([]AWSAccount, error)
}

// ProjectPools resolves the current pool binding, defaulting to the project id
// when that region has no mapping.
type ProjectPools interface {
	ProjectPool(context.Context, resource.AccountID, string) (string, error)
}

// ProxmoxRegion is one registered Proxmox cluster.
type ProxmoxRegion struct {
	Name string
	Kind resource.RegionKind `json:"-"`
	// Endpoint is the region layer's internal API. It is empty for a region
	// this process serves itself.
	Endpoint string
	Zones    []Zone
}

// Zone is a node group of a Proxmox region. Its name is the region name
// followed by Letter.
type Zone struct {
	Letter string   `json:"letter"`
	Nodes  []string `json:"nodes"`
}

// AWSAccount is one registered AWS account and the regions it may use.
type AWSAccount struct {
	ID             string
	AllowedRegions []string
}

// HasRegion reports whether c lists name as a Proxmox region or as a region
// of an AWS account.
func HasRegion(ctx context.Context, c RegionCatalog, name string) (bool, error) {
	pve, err := c.ProxmoxRegions(ctx)
	if err != nil {
		return false, fmt.Errorf("list proxmox regions: %w", err)
	}
	if slices.ContainsFunc(pve, func(r ProxmoxRegion) bool { return r.Name == name }) {
		return true, nil
	}
	accounts, err := c.AWSAccounts(ctx)
	if err != nil {
		return false, fmt.Errorf("list aws accounts: %w", err)
	}
	return slices.ContainsFunc(accounts, func(a AWSAccount) bool {
		return slices.Contains(a.AllowedRegions, name)
	}), nil
}

// StaticRegions is a RegionCatalog held in memory.
type StaticRegions struct {
	mu       sync.RWMutex
	proxmox  []ProxmoxRegion
	accounts []AWSAccount
}

// NewStaticRegions returns a catalog holding regions and accounts.
func NewStaticRegions(regions []ProxmoxRegion, accounts []AWSAccount) *StaticRegions {
	return &StaticRegions{proxmox: cloneRegions(regions), accounts: cloneAccounts(accounts)}
}

// DefaultRegions returns a catalog holding the one region this process
// serves itself, resource.RegionName with the zone resource.ZoneName.
func DefaultRegions() *StaticRegions {
	return NewStaticRegions([]ProxmoxRegion{{Name: resource.RegionName, Zones: []Zone{{Letter: "a"}}}}, nil)
}

// ProxmoxRegions returns a copy of the Proxmox regions.
func (s *StaticRegions) ProxmoxRegions(context.Context) ([]ProxmoxRegion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRegions(s.proxmox), nil
}

// AWSAccounts returns a copy of the AWS accounts.
func (s *StaticRegions) AWSAccounts(context.Context) ([]AWSAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneAccounts(s.accounts), nil
}

// AddProxmoxRegion registers r, replacing a region of the same name.
func (s *StaticRegions) AddProxmoxRegion(r ProxmoxRegion) {
	r = cloneRegions([]ProxmoxRegion{r})[0]
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proxmox = slices.DeleteFunc(s.proxmox, func(old ProxmoxRegion) bool { return old.Name == r.Name })
	s.proxmox = append(s.proxmox, r)
}

func cloneRegions(in []ProxmoxRegion) []ProxmoxRegion {
	out := slices.Clone(in)
	for i := range out {
		out[i].Zones = slices.Clone(out[i].Zones)
		for j := range out[i].Zones {
			out[i].Zones[j].Nodes = slices.Clone(out[i].Zones[j].Nodes)
		}
	}
	return out
}

func cloneAccounts(in []AWSAccount) []AWSAccount {
	out := slices.Clone(in)
	for i := range out {
		out[i].AllowedRegions = slices.Clone(out[i].AllowedRegions)
	}
	return out
}
