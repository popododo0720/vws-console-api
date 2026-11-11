// Package pvefake is an in-memory Proxmox VE API for tests: the read paths
// pveclient calls, answered in the api-viewer shapes, behind API tokens whose
// ACLs are checked as PVE checks them (design.md 8.1). A Fake is an
// http.Handler that tests serve with httptest.
package pvefake

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Scenario is the state a Fake starts from.
type Scenario struct {
	// Version is what GET /version answers: the PVE release the shapes follow.
	Version Version `yaml:"version"`
	// Cluster is the corosync cluster name. Empty is a standalone node, whose
	// /cluster/status has no type=cluster row.
	Cluster  string    `yaml:"cluster"`
	Nodes    []Node    `yaml:"nodes"`
	VMs      []VM      `yaml:"vms"`
	Pools    []string  `yaml:"pools"`
	Roles    []Role    `yaml:"roles"`
	Tokens   []Token   `yaml:"tokens"`
	Storages []Storage `yaml:"storages"`
	Networks []Network `yaml:"networks"`
}

// Network is one node's bridge interface.
type Network struct {
	Node  string `yaml:"node"`
	Iface string `yaml:"iface"`
	Type  string `yaml:"type"`
	CIDR  string `yaml:"cidr"`
}

// Storage is one node's storage inventory entry.
type Storage struct {
	Node string `yaml:"node"`
	Name string `yaml:"name"`

	Content []StorageContent `yaml:"content"`
}

// StorageContent is one disk image in a scenario's storage.
type StorageContent struct {
	VolID   string `yaml:"volid" json:"volid"`
	Content string `yaml:"content" json:"content"`
	Format  string `yaml:"format" json:"format"`
	Size    int64  `yaml:"size" json:"size"`
	VMID    int    `yaml:"vmid" json:"vmid"`
}

// Snapshot is a saved VM state; the API also synthesizes the current entry.
type Snapshot struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
	Parent      string `yaml:"parent" json:"parent"`
	SnapTime    int64  `yaml:"snaptime" json:"snaptime"`
	VMState     int    `yaml:"vmstate" json:"vmstate"`
}

// Version is GET /version.
type Version struct {
	Version string `yaml:"version"`
	Release string `yaml:"release"`
	RepoID  string `yaml:"repoid"`
}

// Node is one cluster node. The first node is the one the API answers from.
type Node struct {
	Name   string `yaml:"name"`
	MaxCPU int    `yaml:"maxcpu"`
	MaxMem int64  `yaml:"maxmem"`
}

// VM is one QEMU guest or template. Config holds the config keys other than
// name, tags and template, such as smbios1, cores and net0.
type VM struct {
	VMID     int               `yaml:"vmid"`
	Node     string            `yaml:"node"`
	Name     string            `yaml:"name"`
	Status   string            `yaml:"status"`
	Pool     string            `yaml:"pool"`
	Tags     string            `yaml:"tags"`
	Template bool              `yaml:"template"`
	MaxCPU   int               `yaml:"maxcpu"`
	MaxMem   int64             `yaml:"maxmem"`
	Config   map[string]string `yaml:"config"`

	Snapshots []Snapshot `yaml:"snapshots"`
}

// Role is a named privilege set, as GET /access/roles lists it.
type Role struct {
	ID    string   `yaml:"id"`
	Privs []string `yaml:"privs"`
}

// Token is an API token, user@realm!name, with its own ACL (privsep=1).
type Token struct {
	ID     string `yaml:"id"`
	Secret string `yaml:"secret"`
	ACL    []ACE  `yaml:"acl"`
}

// ACE grants Role on Path. Propagate nil is PVE's default, true.
type ACE struct {
	Path      string `yaml:"path"`
	Role      string `yaml:"role"`
	Propagate *bool  `yaml:"propagate"`
}

func (a ACE) propagates() bool { return a.Propagate == nil || *a.Propagate }

// Load reads a YAML scenario file.
func Load(path string) (Scenario, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Scenario{}, fmt.Errorf("pvefake: %w", err)
	}
	return Parse(b)
}

// Parse decodes a YAML scenario; New checks it. Unknown keys are refused.
func Parse(b []byte) (Scenario, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var s Scenario
	if err := dec.Decode(&s); err != nil {
		return Scenario{}, fmt.Errorf("pvefake: decode scenario: %w", err)
	}
	return s, nil
}

func (s Scenario) check() error {
	if s.Version.Version == "" || s.Version.Release == "" {
		return errors.New("version.version and version.release name the PVE release the shapes follow")
	}
	if len(s.Nodes) == 0 {
		return errors.New("no nodes")
	}
	if len(s.Nodes) > 1 && s.Cluster == "" {
		return errors.New("several nodes need a cluster name; only a standalone node has none")
	}
	nodes := map[string]bool{}
	for _, n := range s.Nodes {
		if n.Name == "" || nodes[n.Name] {
			return fmt.Errorf("node %q is empty or repeated", n.Name)
		}
		nodes[n.Name] = true
	}
	vms := map[int]bool{}
	for _, vm := range s.VMs {
		if vm.VMID < 100 || vms[vm.VMID] || !nodes[vm.Node] {
			return fmt.Errorf("vm %d: vmid below 100, repeated, or on unknown node %q", vm.VMID, vm.Node)
		}
		vms[vm.VMID] = true
	}
	roles := map[string]bool{}
	for _, r := range s.Roles {
		if roles[r.ID] {
			return fmt.Errorf("role %q is repeated", r.ID)
		}
		roles[r.ID] = true
	}
	tokens := map[string]bool{}
	for _, t := range s.Tokens {
		user, name, ok := strings.Cut(t.ID, "!")
		if !ok || !strings.Contains(user, "@") || name == "" || t.Secret == "" || tokens[t.ID] {
			return fmt.Errorf("token %q is repeated or not user@realm!name with a secret", t.ID)
		}
		tokens[t.ID] = true
		for _, a := range t.ACL {
			if a.Path != path.Clean(a.Path) || !path.IsAbs(a.Path) || !roles[a.Role] {
				return fmt.Errorf("token %q: acl path %q is not clean and absolute, or role %q is unknown", t.ID, a.Path, a.Role)
			}
		}
	}
	return nil
}

// clone copies every slice, map and pointer, so the Fake shares no memory
// with the caller.
func (s Scenario) clone() Scenario {
	s.Nodes, s.VMs = slices.Clone(s.Nodes), slices.Clone(s.VMs)
	s.Pools = slices.Clone(s.Pools)
	s.Roles, s.Tokens = slices.Clone(s.Roles), slices.Clone(s.Tokens)
	s.Storages = slices.Clone(s.Storages)
	s.Networks = slices.Clone(s.Networks)
	for i := range s.VMs {
		s.VMs[i].Config = maps.Clone(s.VMs[i].Config)
		s.VMs[i].Snapshots = slices.Clone(s.VMs[i].Snapshots)
	}
	for i := range s.Storages {
		s.Storages[i].Content = slices.Clone(s.Storages[i].Content)
	}
	for i := range s.Roles {
		s.Roles[i].Privs = slices.Clone(s.Roles[i].Privs)
	}
	for i := range s.Tokens {
		acl := slices.Clone(s.Tokens[i].ACL)
		for j, a := range acl {
			p := a.propagates()
			acl[j].Propagate = &p
		}
		s.Tokens[i].ACL = acl
	}
	return s
}
