package cloud

import (
	"context"
	"slices"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// CreateVolume accepts a volume in one of the caller region's declared zones.
func (s *Service) CreateVolume(ctx context.Context, c resource.Caller,
	token resource.ClientToken, req resource.CreateVolumeRequest,
) (acc resource.Accepted[resource.Volume], err error) {
	defer s.startMutation(&ctx, c, req)(ctx, &acc.Operation, &err)
	token, err = fillToken(token)
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	if err := requireCaller(c); err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	caps, err := s.caps.RegionCapabilities(ctx, s.capabilityRegion(c.Region))
	if err != nil {
		return resource.Accepted[resource.Volume]{}, err
	}
	zones := caps.Zones
	if len(zones) == 0 {
		return resource.Accepted[resource.Volume]{}, resource.Invalid("availabilityZone", "no zones available in region")
	}
	if req.Zone == "" {
		req.Zone = zones[0].ZoneName
	}
	if !slices.ContainsFunc(zones, func(zone resource.RegionZone) bool { return zone.ZoneName == req.Zone }) {
		return resource.Accepted[resource.Volume]{}, resource.Invalid("availabilityZone", "unsupported")
	}
	return mutate(ctx, s, c, token, req, s.backends.Compute.CreateVolume)
}
