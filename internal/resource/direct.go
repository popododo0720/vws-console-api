package resource

import "strings"

// A direct network is a provider network vws-network shares with every
// project (vws-deploy#125). Each is a subnet "subnet-direct-<name>" in the
// VPC "vpc-direct". Every account sees it, and no account can create, change
// or delete it.
const (
	directVpc          = "vpc-direct"
	directSubnetPrefix = "subnet-direct-"
	// DirectNetworkTagKey and DirectNetworkTagValue are the tag a direct
	// subnet carries, the label vws-network sets on it.
	DirectNetworkTagKey   = "vws:network-type"
	DirectNetworkTagValue = "direct"
)

// DirectVpcID is the VPC every direct subnet is in.
func DirectVpcID() VpcID { return VpcID{v: directVpc} }

// IsDirectVpc reports whether id is the direct VPC.
func IsDirectVpc(id VpcID) bool { return id.v == directVpc }

// IsDirectSubnet reports whether id names a direct subnet.
func IsDirectSubnet(id SubnetID) bool { return strings.HasPrefix(id.v, directSubnetPrefix) }

// DirectReadOnly refuses a write to a direct network. EC2 answers
// UnauthorizedOperation, as vws-network does.
func DirectReadOnly() *Error { return Denied("direct networks are read-only") }

// validDirectSubnet is the vws-network direct name rule,
// ^[a-z][a-z0-9-]{0,14}$, after the prefix.
func validDirectSubnet(s string) bool {
	name, ok := strings.CutPrefix(s, directSubnetPrefix)
	if !ok || len(name) < 1 || len(name) > 15 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case i > 0 && (r >= '0' && r <= '9' || r == '-'):
		default:
			return false
		}
	}
	return true
}
