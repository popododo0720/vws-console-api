package proxmox

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sort"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// bridge is one cluster bridge with its ids. Subnet is set only when CIDR is.
type bridge struct {
	Iface  string
	CIDR   string
	VPC    resource.VpcID
	Subnet resource.SubnetID
}

// bridges merges the same cluster bridge seen on several online nodes.
// Configuration wins over the nodes' host addresses. Without configuration a
// bridge has a CIDR only when every online node that reports one masks to the
// same network, so the subnet never depends on which node answers first.
// A bridge whose ids cannot be derived is skipped, never failing the listing.
func (b *Backend) bridges(ctx context.Context) ([]bridge, error) {
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return nil, err
	}
	nodes, err := b.client.Nodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("proxmox: list network nodes: %w", err)
	}
	host := map[string]map[string]bool{}
	for _, node := range nodes {
		if node.Status != "online" {
			continue
		}
		rows, err := b.client.Network(ctx, node.Node)
		if err != nil {
			return nil, fmt.Errorf("proxmox: read bridges on %s: %w", node.Node, err)
		}
		for _, row := range rows {
			if row.Type != "bridge" && row.Type != "OVSBridge" {
				continue
			}
			if host[row.Iface] == nil {
				host[row.Iface] = map[string]bool{}
			}
			if row.CIDR != "" {
				host[row.Iface][row.CIDR] = true
			}
		}
	}
	var out []bridge
	for _, iface := range slices.Sorted(maps.Keys(host)) {
		vpc, err := ids.BridgeVPC(iface)
		if err != nil {
			slog.WarnContext(ctx, "skipping invalid bridge", slog.String("iface", iface), slog.Any("error", err))
			continue
		}
		br := bridge{Iface: iface, VPC: vpc}
		var cidrs []string
		if cfg, ok := b.cfg.Subnets[iface]; ok {
			cidrs = []string{cfg.CIDR}
		} else {
			cidrs = slices.Sorted(maps.Keys(host[iface]))
		}
		networks := map[string]bool{}
		for _, cidr := range cidrs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil || !prefix.Addr().Is4() {
				slog.WarnContext(ctx, "skipping invalid bridge CIDR", slog.String("iface", iface), slog.String("cidr", cidr))
				continue
			}
			networks[prefix.Masked().String()] = true
		}
		switch len(networks) {
		case 0:
		case 1:
			br.CIDR = slices.Collect(maps.Keys(networks))[0]
			subnet, err := ids.BridgeSubnet(iface, br.CIDR)
			if err != nil {
				slog.WarnContext(ctx, "skipping bridge subnet", slog.String("iface", iface), slog.Any("error", err))
				br.CIDR = ""
			} else {
				br.Subnet = subnet
			}
		default:
			slog.WarnContext(ctx, "bridge nodes disagree on its network; set subnets in region.yaml",
				slog.String("iface", iface), slog.Any("cidrs", slices.Sorted(maps.Keys(networks))))
		}
		out = append(out, br)
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
	var out []resource.Vpc
	for _, row := range rows {
		if len(q.IDs) == 0 || slices.Contains(q.IDs, row.VPC) {
			out = append(out, resource.Vpc{
				ID: row.VPC, OwnerID: s.Account, Cidr: row.CIDR,
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
	var out []resource.Subnet
	for _, row := range rows {
		if row.CIDR == "" {
			continue
		}
		if len(q.IDs) == 0 || slices.Contains(q.IDs, row.Subnet) {
			out = append(out, resource.Subnet{
				ID: row.Subnet, OwnerID: s.Account, VpcID: row.VPC, Cidr: row.CIDR,
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
