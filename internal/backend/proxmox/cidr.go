package proxmox

import (
	"net/netip"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// CheckVPCCIDR accepts canonical global-unicast IPv4 from /16 through /28.
func CheckVPCCIDR(p netip.Prefix) error {
	if err := canonicalIPv4(p); err != nil {
		return err
	}
	if p.Bits() < 16 || p.Bits() > 28 {
		return resource.InvalidVpcRange()
	}
	// IsGlobalUnicast rejects only 0.0.0.0 itself, not the rest of 0.0.0.0/8.
	if p.Addr().As4()[0] == 0 || !p.Addr().IsGlobalUnicast() {
		return resource.Invalid("cidrBlock", "vpc cidr must be global unicast")
	}
	return nil
}

// CheckSubnetCIDR accepts canonical IPv4 inside vpc, through /28.
func CheckSubnetCIDR(vpc, p netip.Prefix) error {
	if err := canonicalIPv4(p); err != nil {
		return err
	}
	if !vpc.IsValid() || !vpc.Addr().Is4() || vpc.Bits() > p.Bits() || p.Bits() > 28 || !vpc.Contains(p.Addr()) {
		return resource.Invalid("cidrBlock", "subnet cidr must be inside the vpc and no longer than /28")
	}
	return nil
}

func canonicalIPv4(p netip.Prefix) error {
	if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() {
		return resource.Invalid("cidrBlock", "cidr must be a canonical ipv4 prefix")
	}
	return nil
}
