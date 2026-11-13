package pveclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Version is GET /version.
type Version struct {
	Version string `json:"version"`
	Release string `json:"release"`
	RepoID  string `json:"repoid"`
}

// ClusterStatus is one entry of GET /cluster/status: the cluster or a node.
type ClusterStatus struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Online  int    `json:"online"`
	Local   int    `json:"local"`
	Quorate int    `json:"quorate"`
	Nodes   int    `json:"nodes"`
}

// ResourceType filters GET /cluster/resources. The empty type lists all.
type ResourceType string

// Resource types.
const (
	ResourceVM      ResourceType = "vm"
	ResourceNode    ResourceType = "node"
	ResourceStorage ResourceType = "storage"
	ResourceSDN     ResourceType = "sdn"
)

// ClusterResource is one entry of GET /cluster/resources.
type ClusterResource struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"`
	Node     string  `json:"node"`
	Status   string  `json:"status"`
	Name     string  `json:"name"`
	VMID     int     `json:"vmid"`
	Pool     string  `json:"pool"`
	Tags     string  `json:"tags"`
	Template int     `json:"template"`
	MaxCPU   float64 `json:"maxcpu"`
	MaxMem   int64   `json:"maxmem"`
	Mem      int64   `json:"mem"`
	Storage  string  `json:"storage"`
	Shared   int     `json:"shared"`
	MaxDisk  int64   `json:"maxdisk"`
	Disk     int64   `json:"disk"`
}

// Node is one entry of GET /nodes.
type Node struct {
	Node   string  `json:"node"`
	Status string  `json:"status"`
	MaxCPU float64 `json:"maxcpu"`
	MaxMem int64   `json:"maxmem"`
	Mem    int64   `json:"mem"`
}

// VMConfig is GET /nodes/{node}/qemu/{vmid}/config. Digest goes back on
// every config write (design.md 3.3.6).
type VMConfig struct {
	Digest      string `json:"digest"`
	Name        string `json:"name"`
	Tags        string `json:"tags"`
	Lock        string `json:"lock"`
	Template    int    `json:"template"`
	SMBIOS1     string `json:"smbios1"`
	Meta        string `json:"meta"`
	Cores       int    `json:"cores"`
	Sockets     int    `json:"sockets"`
	Memory      int    `json:"memory"`
	Description string `json:"description"`
	QMPStatus   string `json:"qmpstatus"`
	Protection  int    `json:"protection"`
	Net0        string `json:"net0"`
	Serial0     string `json:"serial0"`
	Agent       string `json:"agent"`

	Drives map[string]string `json:"-"`
}

// UnmarshalJSON retains indexed disk keys alongside the fixed config fields.
func (v *VMConfig) UnmarshalJSON(data []byte) error {
	type config VMConfig
	var decoded config
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("pveclient: VM config: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("pveclient: VM config fields: %w", err)
	}
	for key, value := range fields {
		for _, bus := range []string{"scsi", "virtio", "sata", "ide"} {
			suffix, ok := strings.CutPrefix(key, bus)
			index, err := strconv.Atoi(suffix)
			if !ok || err != nil || index < 0 || suffix != strconv.Itoa(index) {
				continue
			}
			var drive string
			if err := json.Unmarshal(value, &drive); err != nil {
				return fmt.Errorf("pveclient: drive %s: %w", key, err)
			}
			if decoded.Drives == nil {
				decoded.Drives = map[string]string{}
			}
			decoded.Drives[key] = drive
		}
	}
	*v = VMConfig(decoded)
	return nil
}

// Snapshot is one entry of GET /nodes/{node}/qemu/{vmid}/snapshot.
type Snapshot struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Parent      string `json:"parent"`
	SnapTime    int64  `json:"snaptime"`
	VMState     int    `json:"vmstate"`
}

// StorageContent is one entry of GET /nodes/{node}/storage/{storage}/content.
type StorageContent struct {
	VolID   string `json:"volid"`
	Content string `json:"content"`
	Format  string `json:"format"`
	Size    int64  `json:"size"`
	VMID    int    `json:"vmid"`
}

// NetworkInterface is one entry of GET /nodes/{node}/network.
type NetworkInterface struct {
	Iface   string `json:"iface"`
	Type    string `json:"type"`
	CIDR    string `json:"cidr"`
	Gateway string `json:"gateway"`
	Active  int    `json:"active"`
}

// SDNZone is one entry of GET /cluster/sdn/zones.
type SDNZone struct {
	Zone string `json:"zone"`
	Type string `json:"type"`
}

// SDNVNet is one entry of GET /cluster/sdn/vnets.
type SDNVNet struct {
	VNet  string `json:"vnet"`
	Zone  string `json:"zone"`
	Tag   int    `json:"tag"`
	Alias string `json:"alias"`
}

// SDNSubnet is one entry of GET /cluster/sdn/vnets/{vnet}/subnets.
type SDNSubnet struct {
	Subnet  string `json:"subnet"`
	CIDR    string `json:"cidr"`
	Gateway string `json:"gateway"`
	SNAT    int    `json:"snat"`
}

// FirewallGroup is one entry of GET /cluster/firewall/groups.
type FirewallGroup struct {
	Group   string `json:"group"`
	Comment string `json:"comment"`
	Digest  string `json:"digest"`
}

// FirewallRule is one entry of GET /cluster/firewall/groups/{group}.
type FirewallRule struct {
	Pos     int    `json:"pos"`
	Type    string `json:"type"`
	Action  string `json:"action"`
	Proto   string `json:"proto"`
	Source  string `json:"source"`
	Dest    string `json:"dest"`
	DPort   string `json:"dport"`
	Enable  int    `json:"enable"`
	Comment string `json:"comment"`
}

// Permissions is GET /access/permissions: path, then privilege, then 1 when
// it propagates.
type Permissions map[string]map[string]int

// Role is one entry of GET /access/roles. Privs is comma separated.
type Role struct {
	RoleID  string `json:"roleid"`
	Privs   string `json:"privs"`
	Special int    `json:"special"`
}

// Version reads GET /version.
func (c *Client) Version(ctx context.Context) (Version, error) {
	return get[Version](ctx, c, "/version", nil)
}

// ClusterStatus reads GET /cluster/status.
func (c *Client) ClusterStatus(ctx context.Context) ([]ClusterStatus, error) {
	return get[[]ClusterStatus](ctx, c, "/cluster/status", nil)
}

// ClusterResources reads GET /cluster/resources of type t.
func (c *Client) ClusterResources(ctx context.Context, t ResourceType) ([]ClusterResource, error) {
	q := url.Values{}
	if t != "" {
		q.Set("type", string(t))
	}
	return get[[]ClusterResource](ctx, c, "/cluster/resources", q)
}

// Nodes reads GET /nodes.
func (c *Client) Nodes(ctx context.Context) ([]Node, error) {
	return get[[]Node](ctx, c, "/nodes", nil)
}

// VM names one QEMU VM.
type VM struct {
	Node string
	VMID int
}

func (vm VM) path() (string, error) {
	if vm.VMID <= 0 {
		return "", fmt.Errorf("pveclient: invalid vmid %d", vm.VMID)
	}
	n, err := segment("node", vm.Node)
	if err != nil {
		return "", err
	}
	return "/nodes" + n + "/qemu/" + strconv.Itoa(vm.VMID), nil
}

// VMConfig reads GET /nodes/{node}/qemu/{vmid}/config.
func (c *Client) VMConfig(ctx context.Context, vm VM) (VMConfig, error) {
	p, err := vm.path()
	if err != nil {
		return VMConfig{}, err
	}
	return get[VMConfig](ctx, c, p+"/config", nil)
}

// Snapshots reads GET /nodes/{node}/qemu/{vmid}/snapshot.
func (c *Client) Snapshots(ctx context.Context, vm VM) ([]Snapshot, error) {
	p, err := vm.path()
	if err != nil {
		return nil, err
	}
	return get[[]Snapshot](ctx, c, p+"/snapshot", nil)
}

// StorageContent reads GET /nodes/{node}/storage/{storage}/content.
func (c *Client) StorageContent(ctx context.Context, node, storage string) ([]StorageContent, error) {
	n, err := segment("node", node)
	if err != nil {
		return nil, err
	}
	s, err := segment("storage", storage)
	if err != nil {
		return nil, err
	}
	return get[[]StorageContent](ctx, c, "/nodes"+n+"/storage"+s+"/content", nil)
}

// Network reads GET /nodes/{node}/network.
func (c *Client) Network(ctx context.Context, node string) ([]NetworkInterface, error) {
	n, err := segment("node", node)
	if err != nil {
		return nil, err
	}
	return get[[]NetworkInterface](ctx, c, "/nodes"+n+"/network", url.Values{"type": {"any_bridge"}})
}

// SDNZones reads GET /cluster/sdn/zones.
func (c *Client) SDNZones(ctx context.Context) ([]SDNZone, error) {
	return get[[]SDNZone](ctx, c, "/cluster/sdn/zones", nil)
}

// SDNVNets reads GET /cluster/sdn/vnets.
func (c *Client) SDNVNets(ctx context.Context) ([]SDNVNet, error) {
	return get[[]SDNVNet](ctx, c, "/cluster/sdn/vnets", nil)
}

// SDNSubnets reads GET /cluster/sdn/vnets/{vnet}/subnets.
func (c *Client) SDNSubnets(ctx context.Context, vnet string) ([]SDNSubnet, error) {
	v, err := segment("vnet", vnet)
	if err != nil {
		return nil, err
	}
	return get[[]SDNSubnet](ctx, c, "/cluster/sdn/vnets"+v+"/subnets", nil)
}

// FirewallGroups reads GET /cluster/firewall/groups.
func (c *Client) FirewallGroups(ctx context.Context) ([]FirewallGroup, error) {
	return get[[]FirewallGroup](ctx, c, "/cluster/firewall/groups", nil)
}

// FirewallGroupRules reads GET /cluster/firewall/groups/{group}.
func (c *Client) FirewallGroupRules(ctx context.Context, group string) ([]FirewallRule, error) {
	g, err := segment("group", group)
	if err != nil {
		return nil, err
	}
	return get[[]FirewallRule](ctx, c, "/cluster/firewall/groups"+g, nil)
}

// AccessPermissions reads GET /access/permissions for the token on path;
// the empty path lists every path.
func (c *Client) AccessPermissions(ctx context.Context, path string) (Permissions, error) {
	q := url.Values{}
	if path != "" {
		q.Set("path", path)
	}
	return get[Permissions](ctx, c, "/access/permissions", q)
}

// Roles reads GET /access/roles.
func (c *Client) Roles(ctx context.Context) ([]Role, error) {
	return get[[]Role](ctx, c, "/access/roles", nil)
}
