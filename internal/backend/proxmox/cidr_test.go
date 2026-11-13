package proxmox

import (
	"net/netip"
	"testing"
)

func TestCheckVPCCIDR(t *testing.T) {
	for _, tc := range []struct {
		cidr string
		ok   bool
	}{
		{"10.0.0.0/16", true},
		{"192.168.0.0/16", true},
		{"172.16.0.0/28", true},
		{"203.0.113.0/24", true},
		{"10.0.0.1/16", false},
		{"10.0.0.0/15", false},
		{"10.0.0.0/29", false},
		{"127.0.0.0/16", false},
		{"169.254.0.0/16", false},
		{"224.0.0.0/16", false},
		{"0.0.0.0/16", false},
		{"0.1.0.0/16", false},
		{"0.255.0.0/16", false},
		{"240.0.0.0/16", true},
		{"::/16", false},
		{"not-a-cidr", false},
	} {
		p, _ := netip.ParsePrefix(tc.cidr)
		if err := CheckVPCCIDR(p); (err == nil) != tc.ok {
			t.Fatalf("CheckVPCCIDR(%s) = %v, want accepted=%v", tc.cidr, err, tc.ok)
		}
	}
}

func TestCheckSubnetCIDR(t *testing.T) {
	vpc := netip.MustParsePrefix("10.0.0.0/16")
	for _, tc := range []struct {
		cidr string
		ok   bool
	}{
		{"10.0.1.0/24", true},
		{"10.0.0.0/16", true},
		{"10.1.0.0/24", false},
		{"10.0.0.0/29", false},
		{"10.0.1.1/24", false},
		{"::/24", false},
		{"invalid", false},
	} {
		p, _ := netip.ParsePrefix(tc.cidr)
		if err := CheckSubnetCIDR(vpc, p); (err == nil) != tc.ok {
			t.Fatalf("CheckSubnetCIDR(%s) = %v, want accepted=%v", tc.cidr, err, tc.ok)
		}
	}
}
