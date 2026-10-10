package resource

// Kind names a sort of resource. The wire name is Kind.String.
type Kind int

// The resource kinds. KindUnspecified is the zero value and is never a
// successful parse.
const (
	KindUnspecified Kind = iota
	KindInstance
	KindImage
	KindReservation
	KindSubnet
	KindBucket
	KindObject
	KindOperation
	KindVpc
	KindVolume
	KindSecurityGroup
	KindKeyPair
	KindAddress
	KindSnapshot
)

// String returns the wire name. An unknown kind returns "".
func (k Kind) String() string {
	switch k {
	case KindInstance:
		return "instance"
	case KindImage:
		return "image"
	case KindReservation:
		return "reservation"
	case KindSubnet:
		return "subnet"
	case KindBucket:
		return "bucket"
	case KindObject:
		return "object"
	case KindOperation:
		return "operation"
	case KindVpc:
		return "vpc"
	case KindVolume:
		return "volume"
	case KindSecurityGroup:
		return "securityGroup"
	case KindKeyPair:
		return "keyPair"
	case KindAddress:
		return "address"
	case KindSnapshot:
		return "snapshot"
	case KindUnspecified:
		return ""
	default:
		return ""
	}
}

type kindInfo struct {
	prefix  string
	service Service
}

func (k Kind) info() kindInfo {
	switch k {
	case KindInstance:
		return kindInfo{prefix: "i-", service: ServiceCompute}
	case KindImage:
		return kindInfo{prefix: "ami-", service: ServiceCompute}
	case KindReservation:
		return kindInfo{prefix: "r-", service: ServiceCompute}
	case KindSubnet:
		return kindInfo{prefix: "subnet-", service: ServiceNetwork}
	case KindBucket:
		return kindInfo{service: ServiceStorage}
	case KindObject:
		return kindInfo{service: ServiceStorage}
	case KindOperation:
		return kindInfo{prefix: "op-", service: ServiceUnspecified}
	case KindVpc:
		return kindInfo{prefix: "vpc-", service: ServiceNetwork}
	case KindVolume:
		return kindInfo{prefix: "vol-", service: ServiceCompute}
	case KindSecurityGroup:
		return kindInfo{prefix: "sg-", service: ServiceNetwork}
	case KindKeyPair:
		return kindInfo{prefix: "key-", service: ServiceCompute}
	case KindAddress:
		return kindInfo{prefix: "eipalloc-", service: ServiceNetwork}
	case KindSnapshot:
		return kindInfo{prefix: "snap-", service: ServiceCompute}
	case KindUnspecified:
		return kindInfo{}
	default:
		return kindInfo{}
	}
}

// Kinds returns every specified kind, in declaration order.
func Kinds() []Kind {
	var out []Kind
	for k := Kind(1); k.String() != ""; k++ {
		out = append(out, k)
	}
	return out
}

// Service names an internal service that owns resources and operations.
type Service int

// The internal services. ServiceUnspecified is the zero value.
const (
	ServiceUnspecified Service = iota
	ServiceCompute
	ServiceStorage
	ServiceNetwork
)

// String returns the wire name used inside an operation id.
func (s Service) String() string {
	switch s {
	case ServiceCompute:
		return "compute"
	case ServiceStorage:
		return "storage"
	case ServiceNetwork:
		return "network"
	case ServiceUnspecified:
		return ""
	default:
		return ""
	}
}

// ParseService returns the service named s.
func ParseService(s string) (Service, bool) {
	for svc := Service(1); svc.String() != ""; svc++ {
		if svc.String() == s {
			return svc, true
		}
	}
	return ServiceUnspecified, false
}
