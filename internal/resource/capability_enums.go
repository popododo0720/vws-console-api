package resource

// ActionState is how a region serves one action.
type ActionState int

// The action states of design.md 3.2.4.
const (
	actionStateNone ActionState = iota
	// ActionSupported serves the action as EC2 does.
	ActionSupported
	// ActionPartial serves the action for some inputs only.
	ActionPartial
	// ActionUnsupported refuses a mutation with UnsupportedOperation.
	ActionUnsupported
	// ActionEmpty answers a read with an empty, successful result.
	ActionEmpty
)

// String returns the wire name. The zero state returns "".
func (s ActionState) String() string {
	switch s {
	case ActionSupported:
		return "supported"
	case ActionPartial:
		return "partial"
	case ActionUnsupported:
		return "unsupported"
	case ActionEmpty:
		return "empty"
	case actionStateNone:
		return ""
	default:
		return ""
	}
}

// MarshalText encodes the wire name.
func (s ActionState) MarshalText() ([]byte, error) {
	if s.String() == "" {
		return nil, Invalid("state", "required")
	}
	return []byte(s.String()), nil
}

// UnmarshalText parses the wire name.
func (s *ActionState) UnmarshalText(b []byte) error {
	for st := ActionSupported; st.String() != ""; st++ {
		if st.String() == string(b) {
			*s = st
			return nil
		}
	}
	return Invalid("state", "unknown")
}

// RegionKind is where a region's resources live.
type RegionKind int

// The region kinds.
const (
	regionKindNone RegionKind = iota
	// RegionKindProxmox is a Proxmox VE cluster.
	RegionKindProxmox
	// RegionKindAWS is an AWS region reached through a registered account.
	RegionKindAWS
)

// String returns the wire name. The zero kind returns "".
func (k RegionKind) String() string {
	switch k {
	case RegionKindProxmox:
		return "proxmox"
	case RegionKindAWS:
		return "aws"
	case regionKindNone:
		return ""
	default:
		return ""
	}
}

// MarshalText encodes the wire name.
func (k RegionKind) MarshalText() ([]byte, error) {
	if k.String() == "" {
		return nil, Invalid("kind", "required")
	}
	return []byte(k.String()), nil
}

// UnmarshalText parses the wire name.
func (k *RegionKind) UnmarshalText(b []byte) error {
	for kind := RegionKindProxmox; kind.String() != ""; kind++ {
		if kind.String() == string(b) {
			*k = kind
			return nil
		}
	}
	return Invalid("kind", "unknown")
}

// ReadAction names an EC2 read the kernel gates by the capability document.
// The other reads of design.md 3.2.4 are not gated yet; a document may still
// name them, as a key this process does not know.
type ReadAction int

// The reads a capability document declares.
const (
	readActionNone ReadAction = iota
	ReadDescribeInstances
	ReadDescribeImages
	ReadDescribeVolumes
	ReadDescribeSnapshots
	ReadDescribeKeyPairs
	ReadDescribeVpcs
	ReadDescribeSubnets
	ReadDescribeSecurityGroups
	ReadDescribeAddresses
)

// String returns the EC2 action name. An unknown read returns "".
func (r ReadAction) String() string {
	names := [...]string{
		readActionNone:             "",
		ReadDescribeInstances:      "DescribeInstances",
		ReadDescribeImages:         "DescribeImages",
		ReadDescribeVolumes:        "DescribeVolumes",
		ReadDescribeSnapshots:      "DescribeSnapshots",
		ReadDescribeKeyPairs:       "DescribeKeyPairs",
		ReadDescribeVpcs:           "DescribeVpcs",
		ReadDescribeSubnets:        "DescribeSubnets",
		ReadDescribeSecurityGroups: "DescribeSecurityGroups",
		ReadDescribeAddresses:      "DescribeAddresses",
	}
	if r < 0 || int(r) >= len(names) {
		return ""
	}
	return names[r]
}

// ReadActions returns every read a capability document declares.
func ReadActions() []ReadAction {
	var out []ReadAction
	for r := ReadAction(1); r.String() != ""; r++ {
		out = append(out, r)
	}
	return out
}
