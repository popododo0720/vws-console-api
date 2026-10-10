package resource

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
	Zone          string            `json:"availabilityZone"`
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
	if !validInstanceType(r.InstanceType) {
		return RunInstancesRequest{}, Invalid("instanceType", "malformed")
	}
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

func validInstanceType(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i, r := range s {
		alnum := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if i == 0 || i == len(s)-1 {
			if !alnum {
				return false
			}
			continue
		}
		if !alnum && r != '.' && r != '-' {
			return false
		}
	}
	return true
}

func validTags(tags map[string]string) error {
	if len(tags) > 20 {
		return Invalid("tags", "too many")
	}
	for k, v := range tags {
		if len(k) < 1 || len(k) > 128 || hasControl(k) {
			return Invalid("tags", "malformed key")
		}
		if len(v) > 256 || hasControl(v) {
			return Invalid("tags", "malformed value")
		}
	}
	return nil
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
	case ActionRunInstances, ActionCreateSubnet, actionNone:
		return 0, 0, Invalid("action", "not an instance transition")
	default:
		return 0, 0, Invalid("action", "not an instance transition")
	}
}
