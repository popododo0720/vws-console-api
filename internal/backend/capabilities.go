package backend

import (
	"context"
	"fmt"
	"maps"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Capabilities answers what each region supports. The kernel reads it on
// every gated call, so a region whose document changes is served by the
// new document without a restart. An implementation returns a document that
// passes resource.RegionCapabilities.Validate.
type Capabilities interface {
	RegionCapabilities(ctx context.Context, region string) (resource.RegionCapabilities, error)
}

type setCapabilities struct {
	set      Set
	provider Capabilities
}

// Capabilities binds the region document to the services this set offers.
func (s Set) Capabilities(provider Capabilities) Capabilities {
	return setCapabilities{set: s, provider: provider}
}

func (s setCapabilities) RegionCapabilities(ctx context.Context, region string) (resource.RegionCapabilities, error) {
	doc, err := s.provider.RegionCapabilities(ctx, region)
	if err != nil {
		return resource.RegionCapabilities{}, fmt.Errorf("backend capabilities: %w", err)
	}
	if s.set.Console == nil && doc.Actions["vws:OpenConsole"].State != resource.ActionUnsupported {
		doc.Actions = maps.Clone(doc.Actions)
		if doc.Actions == nil {
			doc.Actions = map[string]resource.ActionCapability{}
		}
		doc.Actions["vws:OpenConsole"] = resource.ActionCapability{
			State: resource.ActionUnsupported, ReasonCode: "NoConsole", Reason: "backend offers no instance consoles",
		}
	}
	return doc, nil
}

// AllSupported declares every action and read supported in a region of
// Kind. AWS itself answers which EC2 actions it supports; its consoles use
// EC2 Instance Connect instead of the VWS websocket path.
type AllSupported struct {
	Kind resource.RegionKind
}

// RegionCapabilities returns the all-supported document of region.
func (a AllSupported) RegionCapabilities(_ context.Context, region string) (resource.RegionCapabilities, error) {
	actions := map[string]resource.ActionCapability{}
	supported := resource.ActionCapability{State: resource.ActionSupported}
	actions["vws:OpenConsole"] = supported
	if a.Kind == resource.RegionKindAWS {
		actions["vws:OpenConsole"] = resource.ActionCapability{
			State: resource.ActionUnsupported, ReasonCode: "NoConsole", Reason: "use EC2 Instance Connect",
		}
	}
	for _, m := range resource.Actions() {
		actions[m.CapabilityKey()] = supported
	}
	for _, r := range resource.ReadActions() {
		actions[r.CapabilityKey()] = supported
	}
	types := []resource.RegionInstanceType{}
	for _, typ := range resource.InstanceTypes() {
		types = append(types, resource.RegionInstanceType{
			InstanceType: typ.Name, VCPUs: typ.VCPUs, MemoryMiB: typ.MemoryMiB,
		})
	}
	return resource.RegionCapabilities{
		Region: region,
		Kind:   a.Kind,
		Zones: []resource.RegionZone{{
			ZoneName: resource.ZoneName, ZoneID: resource.ZoneName, State: "available",
		}},
		Actions:       actions,
		InstanceTypes: types,
	}, nil
}
