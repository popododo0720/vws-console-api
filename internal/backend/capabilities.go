package backend

import (
	"context"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Capabilities answers what each region supports. The kernel reads it on
// every gated call, so a region whose document changes is served by the
// new document without a restart. An implementation returns a document that
// passes resource.RegionCapabilities.Validate.
type Capabilities interface {
	RegionCapabilities(ctx context.Context, region string) (resource.RegionCapabilities, error)
}

// AllSupported declares every action and read supported in a region of
// Kind. The fake and gRPC backends serve every action, and an AWS region
// takes this document because AWS itself answers what it does not support.
type AllSupported struct {
	Kind resource.RegionKind
}

// RegionCapabilities returns the all-supported document of region.
func (a AllSupported) RegionCapabilities(_ context.Context, region string) (resource.RegionCapabilities, error) {
	actions := map[string]resource.ActionCapability{}
	supported := resource.ActionCapability{State: resource.ActionSupported}
	for _, m := range resource.Actions() {
		actions[m.CapabilityKey()] = supported
	}
	for _, r := range resource.ReadActions() {
		actions[r.CapabilityKey()] = supported
	}
	return resource.RegionCapabilities{
		Region:        region,
		Kind:          a.Kind,
		Zones:         []resource.RegionZone{},
		Actions:       actions,
		InstanceTypes: []resource.RegionInstanceType{},
	}, nil
}
