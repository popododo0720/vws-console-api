package cloud

import (
	"log/slog"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/throttle"
)

// Config wires the kernel.
type Config struct {
	Backends backend.Set
	Audit    *slog.Logger
	// Launches caps RunInstances calls in flight. Nil caps nothing.
	Launches *throttle.Launches
	// Capabilities gates mutations and reads by the region's document. Nil
	// declares every action supported, as the fake and gRPC backends serve.
	Capabilities backend.Capabilities
	// Discovery supplies the public document without the backend-set policy.
	// Nil uses Capabilities.
	Discovery backend.Capabilities
	Regions   backend.RegionCatalog
	Region    string
}

// Service is the single entry the surfaces use.
type Service struct {
	backends  backend.Set
	audit     *slog.Logger
	launches  *throttle.Launches
	caps      backend.Capabilities
	discovery backend.Capabilities
	regions   backend.RegionCatalog
	region    string
}

// New builds a kernel. A nil logger discards audit lines.
func New(cfg Config) *Service {
	if cfg.Audit == nil {
		cfg.Audit = slog.New(slog.DiscardHandler)
	}
	if cfg.Capabilities == nil {
		cfg.Capabilities = backend.AllSupported{Kind: resource.RegionKindProxmox}
	}
	if cfg.Discovery == nil {
		cfg.Discovery = cfg.Capabilities
	}
	if cfg.Regions == nil {
		cfg.Regions = backend.DefaultRegions()
	}
	if cfg.Region == "" {
		cfg.Region = resource.RegionName
	}
	return &Service{
		backends: cfg.Backends, audit: cfg.Audit, launches: cfg.Launches,
		caps:      cfg.Backends.Capabilities(cfg.Capabilities),
		discovery: cfg.Discovery,
		regions:   cfg.Regions,
		region:    cfg.Region,
	}
}

func scope(c resource.Caller) backend.Scope {
	return backend.Scope{Account: c.Account, Region: c.Region, Principal: c.Principal}
}
