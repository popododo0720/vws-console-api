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
}

// Service is the single entry the surfaces use.
type Service struct {
	backends backend.Set
	audit    *slog.Logger
	launches *throttle.Launches
}

// New builds a kernel. A nil logger discards audit lines.
func New(cfg Config) *Service {
	if cfg.Audit == nil {
		cfg.Audit = slog.New(slog.DiscardHandler)
	}
	return &Service{backends: cfg.Backends, audit: cfg.Audit, launches: cfg.Launches}
}

func scope(c resource.Caller) backend.Scope {
	return backend.Scope{Account: c.Account}
}
