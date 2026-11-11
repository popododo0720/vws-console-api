package proxmox

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// bridges merges the same cluster bridge seen on several online nodes.
// Configuration wins over a node's host address, which may differ per node.
func (b *Backend) bridges(ctx context.Context) ([]pveclient.NetworkInterface, error) {
	nodes, err := b.client.Nodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("proxmox: list network nodes: %w", err)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Node < nodes[j].Node })
	seen := map[string]bool{}
	var out []pveclient.NetworkInterface
	for _, node := range nodes {
		if node.Status != "online" {
			continue
		}
		rows, err := b.client.Network(ctx, node.Node)
		if err != nil {
			return nil, fmt.Errorf("proxmox: read bridges on %s: %w", node.Node, err)
		}
		for _, row := range rows {
			if seen[row.Iface] {
				continue
			}
			if row.Type != "bridge" && row.Type != "OVSBridge" {
				continue
			}
			if err := checkPart(row.Iface); err != nil {
				slog.WarnContext(ctx, "skipping invalid bridge", slog.String("iface", row.Iface), slog.Any("error", err))
				continue
			}
			seen[row.Iface] = true
			if cfg, ok := b.cfg.Subnets[row.Iface]; ok {
				row.CIDR = cfg.CIDR
			}
			if row.CIDR != "" {
				prefix, err := netip.ParsePrefix(row.CIDR)
				if err != nil || !prefix.Addr().Is4() {
					slog.WarnContext(ctx, "skipping invalid bridge CIDR",
						slog.String("iface", row.Iface), slog.String("cidr", row.CIDR))
					row.CIDR = ""
				} else {
					row.CIDR = prefix.Masked().String()
				}
			}
			out = append(out, row)
		}
	}
	return out, nil
}

// DescribeVpcs lists the bridge inventory shared by the region's accounts.
func (b *Backend) DescribeVpcs(
	ctx context.Context, s backend.Scope, q resource.VpcQuery,
) (resource.Page[resource.Vpc], error) {
	rows, err := b.bridges(ctx)
	if err != nil {
		return resource.Page[resource.Vpc]{}, err
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return resource.Page[resource.Vpc]{}, err
	}
	var out []resource.Vpc
	for _, row := range rows {
		id, err := ids.BridgeVPC(row.Iface)
		if err != nil {
			return resource.Page[resource.Vpc]{}, err
		}
		if len(q.IDs) == 0 || slices.Contains(q.IDs, id) {
			out = append(out, resource.Vpc{
				ID: id, OwnerID: s.Account, Cidr: row.CIDR,
				State: resource.VpcAvailable, IsDefault: row.Iface == b.cfg.DefaultBridge,
			})
		}
	}
	if len(q.IDs) == 1 && len(out) == 0 {
		return resource.Page[resource.Vpc]{}, resource.NotFound(resource.KindVpc, q.IDs[0].String())
	}
	return networkPage(out, q.Page)
}

// DescribeSubnets lists bridge subnets only when their IPv4 CIDR is known.
func (b *Backend) DescribeSubnets(
	ctx context.Context, s backend.Scope, q resource.SubnetQuery,
) (resource.Page[resource.Subnet], error) {
	rows, err := b.bridges(ctx)
	if err != nil {
		return resource.Page[resource.Subnet]{}, err
	}
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return resource.Page[resource.Subnet]{}, err
	}
	var out []resource.Subnet
	for _, row := range rows {
		if row.CIDR == "" {
			continue
		}
		vpc, err := ids.BridgeVPC(row.Iface)
		if err != nil {
			return resource.Page[resource.Subnet]{}, err
		}
		id, err := ids.BridgeSubnet(row.Iface, row.CIDR)
		if err != nil {
			return resource.Page[resource.Subnet]{}, err
		}
		if len(q.IDs) == 0 || slices.Contains(q.IDs, id) {
			out = append(out, resource.Subnet{
				ID: id, OwnerID: s.Account, VpcID: vpc, Cidr: row.CIDR,
				State: resource.SubnetAvailable, DefaultForAz: row.Iface == b.cfg.DefaultBridge,
			})
		}
	}
	if len(q.IDs) == 1 && len(out) == 0 {
		return resource.Page[resource.Subnet]{}, resource.NotFound(resource.KindSubnet, q.IDs[0].String())
	}
	return networkPage(out, q.Page)
}

func networkPage[T interface{ Identity() string }](items []T, q resource.PageRequest) (resource.Page[T], error) {
	q, err := q.Normalize()
	if err != nil {
		return resource.Page[T]{}, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Identity() < items[j].Identity() })
	start := 0
	if q.Token != "" {
		i := slices.IndexFunc(items, func(item T) bool { return item.Identity() == q.Token })
		if i < 0 {
			return resource.Page[T]{}, resource.Invalid("pageToken", "unknown")
		}
		start = i + 1
	}
	end := min(start+q.Size, len(items))
	next := ""
	if end < len(items) {
		next = items[end-1].Identity()
	}
	return resource.Page[T]{Items: items[start:end], NextToken: next}, nil
}
