package resource

import (
	"maps"
	"slices"
)

// RegionCapabilities is what one region supports, the capability document
// of design.md 3.2.4. The kernel and the console read it to refuse a
// mutation or answer a read with an empty result.
type RegionCapabilities struct {
	Region        string                      `json:"region"`
	Kind          RegionKind                  `json:"kind"`
	Cluster       *RegionCluster              `json:"cluster,omitempty"`
	Zones         []RegionZone                `json:"zones"`
	Actions       map[string]ActionCapability `json:"actions"`
	InstanceTypes []RegionInstanceType        `json:"instanceTypes"`
	Limits        RegionLimits                `json:"limits"`
	Features      RegionFeatures              `json:"features"`
}

// RegionCluster is the Proxmox cluster behind a region. An AWS region has none.
type RegionCluster struct {
	Name       string `json:"name"`
	PVERelease string `json:"pveRelease"`
	Quorate    bool   `json:"quorate"`
	Leader     string `json:"leader"`
}

// RegionZone is one zone of a region.
type RegionZone struct {
	ZoneName string   `json:"zoneName"`
	ZoneID   string   `json:"zoneId"`
	State    string   `json:"state"`
	Nodes    []string `json:"nodes,omitempty"`
}

// RegionInstanceType is one instance type a region launches.
type RegionInstanceType struct {
	InstanceType string `json:"instanceType"`
	VCPUs        int    `json:"vcpus"`
	MemoryMiB    int    `json:"memoryMiB"`
}

// RegionLimits are the per-request and per-resource limits of a region.
type RegionLimits struct {
	MaxInstancesPerRun    int `json:"maxInstancesPerRun"`
	MaxTagsPerResource    int `json:"maxTagsPerResource"`
	MaxUserDataBytes      int `json:"maxUserDataBytes"`
	MaxVolumesPerInstance int `json:"maxVolumesPerInstance"`
}

// RegionFeatures are the region's behaviors that are not one action.
type RegionFeatures struct {
	UserData      bool   `json:"userData"`
	LinkedClones  bool   `json:"linkedClones"`
	SnapshotScope string `json:"snapshotScope"`
	PrivateIPMode string `json:"privateIpMode"`
	// LiveTests is region.yaml live_tests; the live runner refuses a region without it.
	LiveTests bool `json:"liveTests"`
}

// ActionCapability is how a region serves one action. Partial and
// unsupported carry the reason a user sees and a code a program reads.
type ActionCapability struct {
	State      ActionState `json:"state"`
	ReasonCode string      `json:"reasonCode,omitempty"`
	Reason     string      `json:"reason,omitempty"`
	Kinds      []string    `json:"kinds,omitempty"`
}

// CapabilityKey is the action's key in RegionCapabilities.Actions.
func (a Action) CapabilityKey() string { return "ec2:" + a.String() }

// CapabilityKey is the read's key in RegionCapabilities.Actions.
func (r ReadAction) CapabilityKey() string { return "ec2:" + r.String() }

// Mutation returns how the region serves a. An action the document does
// not name is unsupported.
func (c RegionCapabilities) Mutation(a Action) ActionCapability {
	if got, ok := c.Actions[a.CapabilityKey()]; ok {
		return got
	}
	return ActionCapability{State: ActionUnsupported, ReasonCode: "NotDeclared", Reason: "not declared by the region"}
}

// Read returns how the region serves r. A read the document does not name
// answers an empty result, the read form of unsupported.
func (c RegionCapabilities) Read(r ReadAction) ActionCapability {
	if got, ok := c.Actions[r.CapabilityKey()]; ok {
		return got
	}
	return ActionCapability{State: ActionEmpty}
}

// Validate checks the document a region sends. A mutation is never empty,
// a read is never unsupported, and partial and unsupported name a reason
// and a reason code. A key this process does not know is kept, so a newer
// region can declare actions an older global layer does not serve.
func (c RegionCapabilities) Validate() error {
	if c.Region == "" {
		return Invalid("region", "required")
	}
	if c.Kind == regionKindNone {
		return Invalid("kind", "required")
	}
	mutations := map[string]bool{}
	for _, a := range Actions() {
		mutations[a.CapabilityKey()] = true
	}
	reads := map[string]bool{}
	for _, r := range ReadActions() {
		reads[r.CapabilityKey()] = true
	}
	for _, key := range slices.Sorted(maps.Keys(c.Actions)) {
		field := "actions." + key
		got := c.Actions[key]
		switch got.State {
		case actionStateNone:
			return Invalid(field+".state", "required")
		case ActionPartial, ActionUnsupported:
			if got.Reason == "" || got.ReasonCode == "" {
				return Invalid(field, got.State.String()+" needs reason and reasonCode")
			}
		case ActionSupported, ActionEmpty:
		}
		if mutations[key] && got.State == ActionEmpty {
			return Invalid(field, "a mutation is never empty")
		}
		if reads[key] && got.State == ActionUnsupported {
			return Invalid(field, "a read is never unsupported")
		}
	}
	return nil
}
