package regionapi

import (
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
)

func TestInvalidConfigDoesNotPanic(t *testing.T) {
	defer func() {
		if value := recover(); value != nil {
			t.Fatalf("invalid configuration panicked: %v", value)
		}
	}()
	if h, err := New(Config{}); err == nil || h != nil || !strings.Contains(err.Error(), "new region API") {
		t.Fatalf("handler=%v error=%v", h, err)
	}
	for _, clear := range []func(*Config){
		func(c *Config) { c.Backend.Compute = nil },
		func(c *Config) { c.Backend.Network = nil },
		func(c *Config) { c.Backend.Storage = nil },
		func(c *Config) { c.Capabilities = nil },
		func(c *Config) { c.Region = "" },
		func(c *Config) { c.Version.ReleaseLine = "" },
		func(c *Config) { c.Version.ClusterName = "" },
	} {
		cfg := config(fake.New(fake.Options{}).Set())
		clear(&cfg)
		if _, err := New(cfg); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}
