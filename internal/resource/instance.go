package resource

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// InstanceState is the life of an instance. The names are the EC2 state names.
type InstanceState int

// The instance states.
const (
	instanceStateNone InstanceState = iota
	InstancePending
	InstanceRunning
	InstanceStopping
	InstanceStopped
	InstanceShuttingDown
	InstanceTerminated
)

// String returns the wire name.
func (s InstanceState) String() string {
	switch s {
	case InstancePending:
		return "pending"
	case InstanceRunning:
		return "running"
	case InstanceStopping:
		return "stopping"
	case InstanceStopped:
		return "stopped"
	case InstanceShuttingDown:
		return "shutting-down"
	case InstanceTerminated:
		return "terminated"
	case instanceStateNone:
		return ""
	default:
		return ""
	}
}

// ParseInstanceState returns the state named s.
func ParseInstanceState(s string) (InstanceState, bool) {
	for st := InstanceState(1); st.String() != ""; st++ {
		if st.String() == s {
			return st, true
		}
	}
	return instanceStateNone, false
}

// MarshalText encodes the wire name.
func (s InstanceState) MarshalText() ([]byte, error) {
	if s.String() == "" {
		return nil, Invalid("state", "required")
	}
	return []byte(s.String()), nil
}

// UnmarshalText parses the wire name.
func (s *InstanceState) UnmarshalText(b []byte) error {
	parsed, ok := ParseInstanceState(string(b))
	if !ok {
		return Invalid("state", "unknown")
	}
	*s = parsed
	return nil
}

// EC2Code is the numeric code EC2 Query uses for s.
func (s InstanceState) EC2Code() int {
	switch s {
	case InstancePending:
		return 0
	case InstanceRunning:
		return 16
	case InstanceShuttingDown:
		return 32
	case InstanceTerminated:
		return 48
	case InstanceStopping:
		return 64
	case InstanceStopped:
		return 80
	case instanceStateNone:
		return -1
	default:
		return -1
	}
}

// Instance is a virtual machine.
type Instance struct {
	ID            InstanceID        `json:"instanceId"`
	ReservationID ReservationID     `json:"reservationId"`
	OwnerID       AccountID         `json:"ownerId"`
	State         InstanceState     `json:"state"`
	ImageID       ImageID           `json:"imageId"`
	InstanceType  string            `json:"instanceType"`
	SubnetID      SubnetID          `json:"subnetId"`
	VpcID         VpcID             `json:"vpcId,omitzero"`
	Zone          string            `json:"availabilityZone"`
	LaunchTime    time.Time         `json:"launchTime,omitzero"`
	PrivateIP     string            `json:"privateIpAddress,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
}

// Owner returns the account that owns the instance.
func (i Instance) Owner() AccountID { return i.OwnerID }

// Identity returns the instance id.
func (i Instance) Identity() string { return i.ID.String() }

// InstanceStateChange is the accept-time result of StopInstances.
type InstanceStateChange struct {
	ID       InstanceID    `json:"instanceId"`
	OwnerID  AccountID     `json:"ownerId"`
	Previous InstanceState `json:"previousState"`
	Current  InstanceState `json:"currentState"`
}

// Owner returns the account that owns the instance.
func (c InstanceStateChange) Owner() AccountID { return c.OwnerID }

// Identity returns the instance id.
func (c InstanceStateChange) Identity() string { return c.ID.String() }

// RunInstancesRequest launches one or more instances.
type RunInstancesRequest struct {
	ImageID      ImageID           `json:"imageId"`
	InstanceType string            `json:"instanceType"`
	SubnetID     SubnetID          `json:"subnetId"`
	Count        int               `json:"count"`
	Tags         map[string]string `json:"tags,omitempty"`
}

// Action returns RunInstances.
func (RunInstancesRequest) Action() Action { return ActionRunInstances }

// Normalize checks the request and fills the default count.
func (r RunInstancesRequest) Normalize() (RunInstancesRequest, error) {
	if r.ImageID.IsZero() {
		return RunInstancesRequest{}, Invalid("imageId", "required")
	}
	typ, ok := vwsInstanceType(r.InstanceType)
	if !ok {
		return RunInstancesRequest{}, Invalid("instanceType", "unsupported instance type")
	}
	r.InstanceType = typ
	if r.SubnetID.IsZero() {
		return RunInstancesRequest{}, Invalid("subnetId", "required")
	}
	if r.Count == 0 {
		r.Count = 1
	}
	if r.Count < 1 || r.Count > 10 {
		return RunInstancesRequest{}, Invalid("count", "must be from 1 to 10")
	}
	if err := validTags(r.Tags); err != nil {
		return RunInstancesRequest{}, err
	}
	return r, nil
}

// StopInstancesRequest stops instances that are running.
type StopInstancesRequest struct {
	IDs []InstanceID `json:"instanceIds"`
}

// Action returns StopInstances.
func (StopInstancesRequest) Action() Action { return ActionStopInstances }

// Normalize checks that at least one id is present.
func (r StopInstancesRequest) Normalize() (StopInstancesRequest, error) {
	if len(r.IDs) < 1 || len(r.IDs) > 20 {
		return StopInstancesRequest{}, Invalid("instanceIds", "must list from 1 to 20 ids")
	}
	seen := map[InstanceID]struct{}{}
	for _, id := range r.IDs {
		if id.IsZero() {
			return StopInstancesRequest{}, Invalid("instanceIds", "malformed")
		}
		if _, ok := seen[id]; ok {
			return StopInstancesRequest{}, Invalid("instanceIds", "duplicate")
		}
		seen[id] = struct{}{}
	}
	return r, nil
}

// InstanceQuery selects instances.
type InstanceQuery struct {
	IDs    []InstanceID    `json:"instanceIds,omitempty"`
	States []InstanceState `json:"states,omitempty"`
	Page   PageRequest     `json:"page,omitempty"`
}

// Normalize canonicalizes the query.
func (q InstanceQuery) Normalize() (InstanceQuery, error) {
	page, err := q.Page.Normalize()
	if err != nil {
		return InstanceQuery{}, err
	}
	q.Page = page
	if len(q.IDs) > 100 {
		return InstanceQuery{}, Invalid("instanceIds", "too many")
	}
	return q, nil
}

// InstanceType is one machine type vws-compute runs.
type InstanceType struct {
	Name      string `json:"instanceType"`
	VCPUs     int    `json:"vcpus"`
	MemoryMiB int    `json:"memoryMiB"`
}

// InstanceTypes is the vws-compute machine catalog, smallest first.
// vws-compute has no RPC that lists it; keep it in step with vwsInstanceType.
func InstanceTypes() []InstanceType {
	return []InstanceType{
		{Name: "vws.small", VCPUs: 1, MemoryMiB: 1024},
		{Name: "vws.medium", VCPUs: 2, MemoryMiB: 4096},
		{Name: "vws.large", VCPUs: 4, MemoryMiB: 8192},
		{Name: "vws.xlarge", VCPUs: 8, MemoryMiB: 16384},
	}
}

// vwsInstanceType maps an EC2 instance type to the vws-compute machine type
// nearest by vCPU and memory. vws-compute accepts only vws.small (1 vCPU,
// 1 GiB), vws.medium (2, 4 GiB), vws.large (4, 8 GiB), and vws.xlarge
// (8, 16 GiB). Nearest is the least |log2 vCPU ratio| + |log2 memory ratio|;
// a tie takes the smaller type. A vws name maps to itself.
func vwsInstanceType(s string) (string, bool) {
	switch s {
	case "vws.small", "vws.medium", "vws.large", "vws.xlarge":
		return s, true
	case "t2.nano", "t2.micro", "t2.small", "t3.nano", "t3.micro", "t3a.nano", "t3a.micro":
		return "vws.small", true
	case "t2.medium", "t2.large", "t3.small", "t3.medium", "t3.large",
		"t3a.small", "t3a.medium", "t3a.large", "m5.large", "c5.large":
		return "vws.medium", true
	case "t2.xlarge", "t3.xlarge", "t3a.xlarge", "m5.xlarge", "c5.xlarge":
		return "vws.large", true
	case "t2.2xlarge", "t3.2xlarge", "t3a.2xlarge", "m5.2xlarge", "c5.2xlarge":
		return "vws.xlarge", true
	}
	return "", false
}

func validTags(tags map[string]string) error {
	if len(tags) > 20 {
		return Invalid("tags", "too many")
	}
	for k, v := range tags {
		if n := utf8.RuneCountInString(k); n < 1 || n > 128 || !tagText(k) {
			return Invalid("tags", "malformed key")
		}
		if utf8.RuneCountInString(v) > 256 || !tagText(v) {
			return Invalid("tags", "malformed value")
		}
	}
	return nil
}

// tagText reports whether s is valid UTF-8 with no control characters.
// As in EC2, lengths count characters and spaces are allowed.
func tagText(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

// NextInstanceState is the state an instance reaches when action finishes.
// The accept-time state is the transitional one. A zero transitional state
// means the action does not apply.
func NextInstanceState(action Action, from InstanceState) (transitional, settled InstanceState, err error) {
	switch action {
	case ActionStopInstances:
		switch from {
		case InstanceRunning:
			return InstanceStopping, InstanceStopped, nil
		case InstanceStopped:
			return InstanceStopped, InstanceStopped, nil
		case InstancePending, InstanceStopping, InstanceShuttingDown, InstanceTerminated, instanceStateNone:
			return 0, 0, Conflict(KindInstance, "", "instance cannot be stopped from "+from.String())
		default:
			return 0, 0, Conflict(KindInstance, "", "instance cannot be stopped from "+from.String())
		}
	case ActionStartInstances:
		switch from {
		case InstanceStopped:
			return InstancePending, InstanceRunning, nil
		case InstancePending, InstanceRunning, InstanceStopping, InstanceShuttingDown, InstanceTerminated, instanceStateNone:
			return 0, 0, Conflict(KindInstance, "", "instance cannot be started from "+from.String())
		default:
			return 0, 0, Conflict(KindInstance, "", "instance cannot be started from "+from.String())
		}
	case ActionTerminateInstances:
		switch from {
		case InstanceTerminated:
			return InstanceTerminated, InstanceTerminated, nil
		case InstancePending, InstanceRunning, InstanceStopping, InstanceStopped, InstanceShuttingDown:
			return InstanceShuttingDown, InstanceTerminated, nil
		case instanceStateNone:
			return 0, 0, Conflict(KindInstance, "", "instance cannot be terminated from "+from.String())
		default:
			return 0, 0, Conflict(KindInstance, "", "instance cannot be terminated from "+from.String())
		}
	case ActionRunInstances, ActionCreateSubnet, ActionCreateVpc, ActionDeleteVpc, ActionCreateVolume, ActionAttachVolume, ActionDeleteVolume, ActionCreateSecurityGroup, ActionAuthorizeSecurityGroupIngress, ActionCreateKeyPair, ActionDeleteKeyPair, ActionDeleteSecurityGroup, ActionDeleteSubnet, ActionAllocateAddress, ActionReleaseAddress, ActionCreateSnapshot, ActionDeleteSnapshot, ActionAssociateAddress, ActionDisassociateAddress, ActionModifyVolume, actionNone:
		return 0, 0, Invalid("action", "not an instance transition")
	default:
		return 0, 0, Invalid("action", "not an instance transition")
	}
}
