package cloud

import (
	"log/slog"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Config wires the kernel.
type Config struct {
	Backends backend.Set
	Audit    *slog.Logger
}

// Service is the single entry the surfaces use.
type Service struct {
	backends backend.Set
	audit    *slog.Logger
}

// New builds a kernel. A nil logger discards audit lines.
func New(cfg Config) *Service {
	if cfg.Audit == nil {
		cfg.Audit = slog.New(slog.DiscardHandler)
	}
	return &Service{backends: cfg.Backends, audit: cfg.Audit}
}

func scope(c resource.Caller) backend.Scope {
	return backend.Scope{Account: c.Account}
}
