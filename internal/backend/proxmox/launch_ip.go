package proxmox

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type staticRange struct {
	prefix netip.Prefix
	first  netip.Addr
	last   netip.Addr
	gw     netip.Addr
}

func (b *Backend) staticSubnet(subnet resource.SubnetID) (staticRange, error) {
	ids, err := NewIDs(b.cluster)
	if err != nil {
		return staticRange{}, err
	}
	for iface, cfg := range b.cfg.Subnets {
		prefix, err := netip.ParsePrefix(cfg.CIDR)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		prefix = prefix.Masked()
		id, err := ids.BridgeSubnet(iface, prefix.String())
		if err != nil || id != subnet || cfg.Mode != "" && cfg.Mode != "static" {
			continue
		}
		gw, err := netip.ParseAddr(cfg.Gateway)
		if err != nil || !prefix.Contains(gw) {
			return staticRange{}, resource.Invalid("subnets.gateway", "must be an IPv4 address in the subnet")
		}
		last := prefix.Addr().As4()
		for bit := prefix.Bits(); bit < 32; bit++ {
			last[bit/8] |= 1 << (7 - bit%8)
		}
		r := staticRange{prefix: prefix, first: prefix.Addr().Next(), last: netip.AddrFrom4(last).Prev(), gw: gw}
		if cfg.IPRange != "" {
			start, end, ok := strings.Cut(cfg.IPRange, "-")
			first, e1 := netip.ParseAddr(start)
			last, e2 := netip.ParseAddr(end)
			if !ok || e1 != nil || e2 != nil || !prefix.Contains(first) || !prefix.Contains(last) ||
				first.Compare(r.first) < 0 || last.Compare(r.last) > 0 || first.Compare(last) > 0 {
				return staticRange{}, resource.Invalid("subnets.ip_range", "must be an inclusive usable IPv4 start-end range")
			}
			r.first, r.last = first, last
		}
		return r, nil
	}
	return staticRange{}, nil
}

func privateIP(config string) netip.Addr {
	prefix, err := netip.ParsePrefix(option(config, "ip"))
	if err != nil || !prefix.Addr().Is4() {
		return netip.Addr{}
	}
	return prefix.Addr()
}

func (b *Backend) scanStaticIPs(ctx context.Context, subnet resource.SubnetID) (map[netip.Addr]bool, int, error) {
	rows, err := b.staticVMs(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("proxmox: IP inventory: %w", err)
	}
	used, pending := map[netip.Addr]bool{}, 0
	for _, vm := range rows {
		if vm.Type != "qemu" {
			continue
		}
		cfg, err := b.client.VMConfig(ctx, pveclient.VM{Node: vm.Node, VMID: vm.VMID})
		if err != nil {
			return nil, 0, fmt.Errorf("proxmox: IP config for VM %d: %w", vm.VMID, err)
		}
		ip := privateIP(cfg.IPConfig0)
		if ip.IsValid() {
			used[ip] = true
		}
		marker, found, err := ReadLaunchMarker(cfg.Description)
		if err != nil {
			return nil, 0, fmt.Errorf("proxmox: IP reservation for VM %d: %w", vm.VMID, err)
		}
		if found && marker.Subnet == subnet && cfg.Template != 1 &&
			(!ip.IsValid() || configUUID(cfg) != marker.UUID) {
			pending++
		}
	}
	return used, pending, nil
}

func (b *Backend) staticVMs(ctx context.Context) ([]pveclient.ClusterResource, error) {
	permissions, err := b.client.AccessPermissions(ctx, "/vms")
	if err != nil {
		return nil, fmt.Errorf("proxmox: IP inventory permissions: %w", err)
	}
	if permissions["/vms"]["VM.Audit"] != 1 {
		return nil, resource.Denied("proxmox: static allocation requires cluster-wide VM.Audit")
	}
	return b.client.ClusterResources(ctx, pveclient.ResourceVM)
}

func (r *staticRange) free(used map[netip.Addr]bool, count int) (netip.Addr, error) {
	first := netip.Addr{}
	for ip := r.first; ip.IsValid() && ip.Compare(r.last) <= 0; ip = ip.Next() {
		if used[ip] || ip == r.gw {
			continue
		}
		if !first.IsValid() {
			first = ip
		}
		count--
		if count == 0 {
			return first, nil
		}
	}
	return netip.Addr{}, resource.InsufficientFreeAddressesInSubnet()
}

// Fence every pending config before allocating anywhere. An old leader's
// admitted PUT can outlive its lease; its digest must lose to this barrier,
// or its address must already be visible to the subsequent cluster scan.
func (b *Backend) fenceStaticLaunches(ctx context.Context, fence func(context.Context) error) error {
	static := false
	for _, cfg := range b.cfg.Subnets {
		static = static || cfg.Mode == "" || cfg.Mode == "static"
	}
	if !static {
		return nil
	}
	rows, err := b.staticVMs(ctx)
	if err != nil {
		return fmt.Errorf("proxmox: IP fence inventory: %w", err)
	}
	for _, vm := range rows {
		managed := false
		for _, pool := range b.cfg.Pools {
			managed = managed || vm.Pool == pool
		}
		if !managed || vm.Type != "qemu" || vm.Template == 1 {
			continue
		}
		target := pveclient.VM{Node: vm.Node, VMID: vm.VMID}
		cfg, err := b.client.VMConfig(ctx, target)
		if err != nil {
			return fmt.Errorf("proxmox: IP fence config: %w", err)
		}
		marker, found, err := ReadLaunchMarker(cfg.Description)
		if err != nil || !found || cfg.Template == 1 ||
			slices.Contains(strings.Split(cfg.Tags, ";"), "vws.holder") ||
			privateIP(cfg.IPConfig0).IsValid() && configUUID(cfg) == marker.UUID {
			continue
		}
		allowed := false
		for account, pool := range b.cfg.Pools {
			id, err := resource.Parse[resource.AccountID](account)
			allowed = allowed || pool == vm.Pool && (err != nil || id == marker.Account)
		}
		if !allowed {
			continue
		}
		r, err := b.staticSubnet(marker.Subnet)
		if err != nil {
			return err
		}
		if !r.prefix.IsValid() {
			continue
		}
		if cfg.Lock != "" {
			return resource.Conflict(resource.KindInstance, "", "static IP fence requires unlocked clones")
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return fmt.Errorf("proxmox: IP fence nonce: %w", err)
		}
		marker.IPFence = fmt.Sprintf("%x", nonce)
		description, err := WithLaunchMarker(cfg.Description, marker)
		if err != nil {
			return err
		}
		if err := fence(ctx); err != nil {
			return err
		}
		if err := b.client.WriteConfig(ctx, target, cfg.Digest, url.Values{"description": {description}}); err != nil {
			return fmt.Errorf("proxmox: IP fence write: %w", err)
		}
	}
	return nil
}
