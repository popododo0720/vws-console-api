package cloud

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// AvailabilityZones returns the region's zone inventory.
func (s *Service) AvailabilityZones(ctx context.Context, c resource.Caller) ([]resource.RegionZone, error) {
	if err := requireCaller(c); err != nil {
		return nil, err
	}
	caps, err := s.caps.RegionCapabilities(ctx, s.capabilityRegion(c.Region))
	if err != nil {
		return nil, fmt.Errorf("availability zones: %w", err)
	}
	if caps.Zones == nil {
		return []resource.RegionZone{{ZoneName: resource.ZoneName, ZoneID: resource.ZoneName, State: "available"}}, nil
	}
	return caps.Zones, nil
}

// RegionNames reads registrations without contacting a region backend.
func (s *Service) RegionNames(ctx context.Context, c resource.Caller) ([]string, error) {
	regions, err := s.registeredRegions(ctx, c)
	if err != nil {
		return nil, err
	}
	return slices.Sorted(maps.Keys(regions)), nil
}

func (s *Service) registeredRegions(
	ctx context.Context, c resource.Caller,
) (map[string]backend.ProxmoxRegion, error) {
	if err := requireCaller(c); err != nil {
		return nil, err
	}
	regions, err := s.regions.ProxmoxRegions(ctx)
	if err != nil {
		return nil, &resource.Error{Code: resource.CodeUnavailable, Message: "region catalog unavailable"}
	}
	accounts, err := s.regions.AWSAccounts(ctx)
	if err != nil {
		return nil, &resource.Error{Code: resource.CodeUnavailable, Message: "region catalog unavailable"}
	}
	registered := map[string]backend.ProxmoxRegion{}
	for _, region := range regions {
		region.Kind = resource.RegionKindProxmox
		registered[region.Name] = region
	}
	for _, account := range accounts {
		for _, name := range account.AllowedRegions {
			registered[name] = backend.ProxmoxRegion{Name: name, Kind: resource.RegionKindAWS}
		}
	}
	return registered, nil
}

// Regions reads a catalog snapshot with at most eight simultaneous region reads.
func (s *Service) Regions(ctx context.Context, c resource.Caller) ([]resource.RegionSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	regions, err := s.registeredRegions(ctx, c)
	if err != nil {
		return nil, err
	}
	items := make([]resource.RegionSummary, len(regions))
	jobs := make(chan int, len(regions))
	for i, name := range slices.Sorted(maps.Keys(regions)) {
		kind := "pve"
		if regions[name].Kind == resource.RegionKindAWS {
			kind = "aws"
		}
		items[i] = resource.RegionSummary{Name: name, Kind: kind, State: "unavailable"}
		jobs <- i
	}
	close(jobs)
	var reads sync.WaitGroup
	for range min(8, len(regions)) {
		reads.Go(func() {
			for i := range jobs {
				doc, err := s.regionCapabilities(ctx, regions[items[i].Name])
				if err != nil {
					continue
				}
				items[i].State = "available"
				if doc.Cluster != nil && (!doc.Cluster.Quorate || doc.Cluster.Leader == "" || doc.Cluster.PVERelease == "") {
					items[i].State = "degraded"
				}
			}
		})
	}
	reads.Wait()
	return items, nil
}

// RegionCapabilities reads one registered region within the regional read bound.
func (s *Service) RegionCapabilities(
	ctx context.Context, c resource.Caller, name string,
) (resource.RegionCapabilities, error) {
	if err := requireCaller(c); err != nil {
		return resource.RegionCapabilities{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := s.RequestRegion(ctx, c, name); err != nil {
		return resource.RegionCapabilities{}, err
	}
	if name == "" || name == "all" {
		return resource.RegionCapabilities{}, resource.Invalid("region", "a registered region is required")
	}
	regions, err := s.registeredRegions(ctx, c)
	if err != nil {
		return resource.RegionCapabilities{}, err
	}
	return s.regionCapabilities(ctx, regions[name])
}

func (s *Service) regionCapabilities(
	ctx context.Context, region backend.ProxmoxRegion,
) (resource.RegionCapabilities, error) {
	if ctx.Err() != nil {
		return resource.RegionCapabilities{}, &resource.Error{Code: resource.CodeUnavailable, Message: "region unavailable"}
	}
	type result struct {
		doc resource.RegionCapabilities
		err error
	}
	done := make(chan result, 1)
	go func() {
		doc, err := s.discovery(ctx, region)
		done <- result{doc, err}
	}()
	select {
	case got := <-done:
		if got.err == nil {
			return got.doc, nil
		}
	case <-ctx.Done():
	}
	return resource.RegionCapabilities{}, &resource.Error{Code: resource.CodeUnavailable, Message: "region unavailable"}
}

// ReadIsEmpty lets derived surface reads honor an explicit empty capability.
// A missing entry keeps the surface's existing behavior.
func (s *Service) ReadIsEmpty(ctx context.Context, c resource.Caller, action string) (bool, error) {
	region := s.capabilityRegion(c.Region)
	caps, err := s.caps.RegionCapabilities(ctx, region)
	if err != nil {
		return false, fmt.Errorf("capabilities of %s: %w", region, err)
	}
	return caps.Actions["ec2:"+action].State == resource.ActionEmpty, nil
}

// InstanceTypes returns the region's declared catalog, including an empty one.
func (s *Service) InstanceTypes(ctx context.Context, c resource.Caller) ([]resource.InstanceType, error) {
	if err := requireCaller(c); err != nil {
		return nil, err
	}
	caps, err := s.caps.RegionCapabilities(ctx, s.capabilityRegion(c.Region))
	if err != nil {
		return nil, fmt.Errorf("instance types: capabilities of %s: %w", resource.RegionName, err)
	}
	if caps.InstanceTypes == nil {
		return resource.InstanceTypes(), nil
	}
	types := make([]resource.InstanceType, 0, len(caps.InstanceTypes))
	for _, typ := range caps.InstanceTypes {
		types = append(types, resource.InstanceType{
			Name: typ.InstanceType, VCPUs: typ.VCPUs, MemoryMiB: typ.MemoryMiB,
		})
	}
	return types, nil
}

// admit refuses a mutation the region does not serve before the backend sees it.
func (s *Service) admit(ctx context.Context, a resource.Action, region string) error {
	region = s.capabilityRegion(region)
	caps, err := s.mutationCapabilities(ctx, region)
	if err != nil {
		return fmt.Errorf("capabilities of %s: %w", region, err)
	}
	got := caps.Mutation(a)
	switch got.State {
	case resource.ActionSupported, resource.ActionPartial:
		return nil
	case resource.ActionUnsupported, resource.ActionEmpty:
	}
	message := fmt.Sprintf("%s is not supported in region %s", a, region)
	if got.Reason != "" {
		message += ": " + got.Reason
	}
	return resource.Unsupported("Action", message)
}

// served answers a read the region does not serve with an empty page, so a
// client that lists everything, as Terraform does, still succeeds.
func served[Q any, T any](
	s *Service,
	read resource.ReadAction,
	call func(context.Context, backend.Scope, Q) (resource.Page[T], error),
) func(context.Context, backend.Scope, Q) (resource.Page[T], error) {
	return func(ctx context.Context, sc backend.Scope, q Q) (resource.Page[T], error) {
		caps, err := s.caps.RegionCapabilities(ctx, s.capabilityRegion(sc.Region))
		if err != nil {
			return resource.Page[T]{}, fmt.Errorf("capabilities of %s: %w", resource.RegionName, err)
		}
		switch caps.Read(read).State {
		case resource.ActionSupported, resource.ActionPartial:
			return call(ctx, sc, q)
		case resource.ActionEmpty, resource.ActionUnsupported:
		}
		return resource.Page[T]{}, nil
	}
}

func (s *Service) capabilityRegion(region string) string {
	if region == "" {
		return s.region
	}
	return region
}
