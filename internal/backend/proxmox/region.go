package proxmox

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"go.yaml.in/yaml/v3"
)

// RegionConfig holds node-local settings, never registration metadata or secrets.
type RegionConfig struct {
	Now             func() time.Time              `yaml:"-"`
	ReadOnly        bool                          `yaml:"read_only"`
	Storages        map[string]string             `yaml:"storages"`
	Templates       TemplateConfig                `yaml:"templates"`
	InstanceTypes   map[string]InstanceTypeConfig `yaml:"instance_types"`
	Subnets         map[string]SubnetConfig       `yaml:"subnets"`
	DefaultBridge   string                        `yaml:"default_bridge"`
	DefaultProject  string                        `yaml:"default_project"`
	Pools           map[string]string             `yaml:"pools"`
	SnippetsStorage string                        `yaml:"snippets_storage"`
	Scheduler       SchedulerConfig               `yaml:"scheduler"`
	LinkedClones    bool                          `yaml:"linked_clones"`
	LiveTests       bool                          `yaml:"live_tests"`
	ShutdownTimeout int                           `yaml:"shutdown_timeout"`
}

// TemplateConfig selects the templates exposed as images.
type TemplateConfig struct {
	Pool string `yaml:"pool"`
	Tag  string `yaml:"tag"`
}

// InstanceTypeConfig selects a default type; nonzero sizes must match its definition.
type InstanceTypeConfig struct {
	Cores     int `yaml:"cores"`
	MemoryMiB int `yaml:"memory_mib"`
}

// SubnetConfig describes a bridge or VNet's address allocation policy.
type SubnetConfig struct {
	CIDR    string `yaml:"cidr"`
	Gateway string `yaml:"gateway"`
	IPRange string `yaml:"ip_range"`
	Mode    string `yaml:"mode"`
}

// SchedulerConfig holds the node-local placement policy.
type SchedulerConfig struct {
	Policy         string  `yaml:"policy"`
	HostReserveMiB int     `yaml:"host_reserve_mib"`
	MemOvercommit  float64 `yaml:"mem_overcommit"`
	CPUOvercommit  float64 `yaml:"cpu_overcommit"`
}

// LoadRegion reads the node-local region.yaml file.
func LoadRegion(path string) (RegionConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return RegionConfig{}, fmt.Errorf("proxmox: read region.yaml %s: %w", path, err)
	}
	return ParseRegion(b)
}

// ParseRegion rejects unknown fields, repeated keys and extra documents.
func ParseRegion(b []byte) (RegionConfig, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var cfg RegionConfig
	if err := dec.Decode(&cfg); err != nil {
		return RegionConfig{}, fmt.Errorf("proxmox: region.yaml: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return RegionConfig{}, errors.New("proxmox: region.yaml: expected one YAML document")
	}
	return cfg, nil
}
