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
}

// Service is the single entry the surfaces use.
type Service struct {
	backends backend.Set
	audit    *slog.Logger
	launches *throttle.Launches
	caps     backend.Capabilities
}

// New builds a kernel. A nil logger discards audit lines.
func New(cfg Config) *Service {
	if cfg.Audit == nil {
		cfg.Audit = slog.New(slog.DiscardHandler)
	}
	if cfg.Capabilities == nil {
		cfg.Capabilities = backend.AllSupported{Kind: resource.RegionKindProxmox}
	}
	return &Service{backends: cfg.Backends, audit: cfg.Audit, launches: cfg.Launches, caps: cfg.Capabilities}
}

func scope(c resource.Caller) backend.Scope {
	return backend.Scope{Account: c.Account}
}
