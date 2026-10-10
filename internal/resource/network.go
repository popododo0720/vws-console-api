package resource

import "net"

// SubnetState is the life of a subnet.
type SubnetState int

// The subnet states.
const (
	subnetStateNone SubnetState = iota
	SubnetPending
	SubnetAvailable
	SubnetDeleting
)

// String returns the wire name.
func (s SubnetState) String() string {
	switch s {
	case SubnetPending:
		return "pending"
	case SubnetAvailable:
		return "available"
	case SubnetDeleting:
		return "deleting"
	case subnetStateNone:
		return ""
	default:
		return ""
	}
}

// MarshalText encodes the wire name.
func (s SubnetState) MarshalText() ([]byte, error) {
	if s.String() == "" {
		return nil, Invalid("state", "required")
	}
	return []byte(s.String()), nil
}

// UnmarshalText parses the wire name.
func (s *SubnetState) UnmarshalText(b []byte) error {
	switch string(b) {
	case SubnetPending.String():
		*s = SubnetPending
	case SubnetAvailable.String():
		*s = SubnetAvailable
	case SubnetDeleting.String():
		*s = SubnetDeleting
	default:
		return Invalid("state", "unknown")
	}
	return nil
}

// Subnet is a network segment.
type Subnet struct {
	ID      SubnetID    `json:"subnetId"`
	OwnerID AccountID   `json:"ownerId"`
	VpcID   VpcID       `json:"vpcId,omitzero"`
	Cidr    string      `json:"cidrBlock"`
	State   SubnetState `json:"state"`
}

// Owner returns the account that owns the subnet.
func (s Subnet) Owner() AccountID { return s.OwnerID }

// Identity returns the subnet id.
func (s Subnet) Identity() string { return s.ID.String() }

// CreateSubnetRequest allocates a subnet.
type CreateSubnetRequest struct {
	Cidr  string `json:"cidrBlock"`
	VpcID VpcID  `json:"vpcId,omitzero"`
}

// Action returns CreateSubnet.
func (CreateSubnetRequest) Action() Action { return ActionCreateSubnet }

// Normalize checks that cidr is an IPv4 network.
func (r CreateSubnetRequest) Normalize() (CreateSubnetRequest, error) {
	ip, ipNet, err := net.ParseCIDR(r.Cidr)
	if err != nil || ip.To4() == nil {
		return CreateSubnetRequest{}, Invalid("cidrBlock", "must be an ipv4 network")
	}
	r.Cidr = ipNet.String()
	return r, nil
}

// SubnetQuery selects subnets.
type SubnetQuery struct {
	IDs  []SubnetID  `json:"subnetIds,omitempty"`
	Page PageRequest `json:"page,omitempty"`
}

// Normalize canonicalizes the page.
func (q SubnetQuery) Normalize() (SubnetQuery, error) {
	page, err := q.Page.Normalize()
	if err != nil {
		return SubnetQuery{}, err
	}
	q.Page = page
	return q, nil
}

// DeleteSubnetRequest deletes one subnet.
type DeleteSubnetRequest struct {
	ID SubnetID `json:"subnetId"`
}

// Action returns DeleteSubnet.
func (DeleteSubnetRequest) Action() Action { return ActionDeleteSubnet }

// Normalize checks the id.
func (r DeleteSubnetRequest) Normalize() (DeleteSubnetRequest, error) {
	if r.ID.IsZero() {
		return DeleteSubnetRequest{}, Invalid("subnetId", "required")
	}
	return r, nil
}

// DeleteSecurityGroupRequest deletes one group by id or by name.
type DeleteSecurityGroupRequest struct {
	ID   SecurityGroupID `json:"groupId,omitzero"`
	Name string          `json:"groupName,omitempty"`
}

// Action returns DeleteSecurityGroup.
func (DeleteSecurityGroupRequest) Action() Action { return ActionDeleteSecurityGroup }

// Normalize requires an id or a name.
func (r DeleteSecurityGroupRequest) Normalize() (DeleteSecurityGroupRequest, error) {
	if r.ID.IsZero() && r.Name == "" {
		return DeleteSecurityGroupRequest{}, Invalid("groupId", "required")
	}
	return r, nil
}

// SecurityGroupQuery selects security groups.
type SecurityGroupQuery struct {
	IDs   []SecurityGroupID `json:"groupIds,omitempty"`
	Names []string          `json:"groupNames,omitempty"`
	Page  PageRequest       `json:"page,omitempty"`
}

// Normalize canonicalizes the page.
func (q SecurityGroupQuery) Normalize() (SecurityGroupQuery, error) {
	page, err := q.Page.Normalize()
	if err != nil {
		return SecurityGroupQuery{}, err
	}
	q.Page = page
	return q, nil
}
