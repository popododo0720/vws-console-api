package resource

import (
	"strings"
	"time"
)

// Action names a long-running mutation. The names are the EC2 action names,
// shared by the console, the query surface, and operation records.
type Action int

// The long-running actions this process serves.
const (
	actionNone Action = iota
	ActionRunInstances
	ActionStopInstances
	ActionCreateSubnet
)

// String returns the wire name. An unknown action returns "".
func (a Action) String() string {
	switch a {
	case ActionRunInstances:
		return "RunInstances"
	case ActionStopInstances:
		return "StopInstances"
	case ActionCreateSubnet:
		return "CreateSubnet"
	case actionNone:
		return ""
	default:
		return ""
	}
}

// ParseAction returns the action named s.
func ParseAction(s string) (Action, bool) {
	for a := Action(1); a.String() != ""; a++ {
		if a.String() == s {
			return a, true
		}
	}
	return actionNone, false
}

// Actions returns every long-running action, derived from the enum.
func Actions() []Action {
	var out []Action
	for a := Action(1); a.String() != ""; a++ {
		out = append(out, a)
	}
	return out
}

// MarshalText encodes the wire name.
func (a Action) MarshalText() ([]byte, error) {
	if a.String() == "" {
		return nil, Invalid("action", "required")
	}
	return []byte(a.String()), nil
}

// UnmarshalText parses the wire name.
func (a *Action) UnmarshalText(b []byte) error {
	parsed, ok := ParseAction(string(b))
	if !ok {
		return Invalid("action", "unknown")
	}
	*a = parsed
	return nil
}

// OperationID identifies one operation and the service that owns it.
// The wire form is "op-<service>-<16 hex>", for example "op-compute-5f0c2a9e1b7d4c3a".
type OperationID struct {
	service Service
	local   string
}

// NewOperationID builds an id the owning service can route without a lookup table.
// local must be 16 lowercase hex digits. Backends call this. Surfaces do not.
func NewOperationID(s Service, local string) (OperationID, error) {
	if s.String() == "" || !hex16(local) {
		return OperationID{}, Malformed(KindOperation, "op-"+s.String()+"-"+local)
	}
	return OperationID{service: s, local: local}, nil
}

func hex16(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, r := range s {
		if !isHex(r) {
			return false
		}
	}
	return true
}

// Service returns the service that owns the operation.
func (id OperationID) Service() Service { return id.service }

// Local returns the owning service's own name for the operation.
func (id OperationID) Local() string { return id.local }

// IsZero reports whether id is unset.
func (id OperationID) IsZero() bool { return id.service == ServiceUnspecified }

// String returns the wire form.
func (id OperationID) String() string {
	if id.IsZero() {
		return ""
	}
	return "op-" + id.service.String() + "-" + id.local
}

// Ref returns a reference to the operation.
func (id OperationID) Ref() Ref { return Ref{kind: KindOperation, id: id.String()} }

// MarshalText encodes the wire form.
func (id OperationID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }

// UnmarshalText parses the wire form.
func (id *OperationID) UnmarshalText(b []byte) error {
	s := string(b)
	rest, ok := strings.CutPrefix(s, "op-")
	if !ok {
		return Malformed(KindOperation, s)
	}
	svcName, local, ok := strings.Cut(rest, "-")
	svc, known := ParseService(svcName)
	if !ok || !known {
		return Malformed(KindOperation, s)
	}
	parsed, err := NewOperationID(svc, local)
	if err != nil {
		return Malformed(KindOperation, s)
	}
	*id = parsed
	return nil
}

// OperationState is the life of an operation. It moves from running to
// exactly one of succeeded or failed.
type OperationState int

// The operation states.
const (
	operationStateNone OperationState = iota
	OperationRunning
	OperationSucceeded
	OperationFailed
)

// String returns the wire name.
func (s OperationState) String() string {
	switch s {
	case OperationRunning:
		return "running"
	case OperationSucceeded:
		return "succeeded"
	case OperationFailed:
		return "failed"
	case operationStateNone:
		return ""
	default:
		return ""
	}
}

// MarshalText encodes the wire name.
func (s OperationState) MarshalText() ([]byte, error) {
	if s.String() == "" {
		return nil, Invalid("state", "required")
	}
	return []byte(s.String()), nil
}

// UnmarshalText parses the wire name.
func (s *OperationState) UnmarshalText(b []byte) error {
	switch string(b) {
	case OperationRunning.String():
		*s = OperationRunning
	case OperationSucceeded.String():
		*s = OperationSucceeded
	case OperationFailed.String():
		*s = OperationFailed
	default:
		return Invalid("state", "unknown")
	}
	return nil
}

// Operation is the record a caller polls for a long-running mutation.
// OwnerID is the account that accepted the mutation. A poll for another
// account does not return the record.
type Operation struct {
	ID         OperationID    `json:"id"`
	Action     Action         `json:"action"`
	State      OperationState `json:"state"`
	OwnerID    AccountID      `json:"ownerId"`
	Targets    []Ref          `json:"targets"`
	Error      *Error         `json:"error,omitempty"`
	CreateTime time.Time      `json:"createTime"`
	UpdateTime time.Time      `json:"updateTime"`
}

// Accepted is the only result of a long-running mutation.
// Items are the resources the operation targets, in their state at accept time.
type Accepted[T any] struct {
	Operation Operation `json:"operation"`
	Items     []T       `json:"items"`
}

// Page is the only list result.
type Page[T any] struct {
	Items     []T    `json:"items"`
	NextToken string `json:"nextPageToken,omitempty"`
}

// PageRequest is a normalized page size and token.
type PageRequest struct {
	Size  int    `json:"pageSize,omitempty"`
	Token string `json:"pageToken,omitempty"`
}

// Normalize clamps the page size. The default is 50 and the maximum is 100.
func (p PageRequest) Normalize() (PageRequest, error) {
	if p.Size == 0 {
		p.Size = 50
	}
	if p.Size < 1 || p.Size > 100 {
		return PageRequest{}, Invalid("pageSize", "must be from 1 to 100")
	}
	if p.Token != "" && hasControl(p.Token) {
		return PageRequest{}, Invalid("pageToken", "malformed")
	}
	return p, nil
}
