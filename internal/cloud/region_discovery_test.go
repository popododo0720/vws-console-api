package cloud

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type discoveryCatalog struct {
	backend.RegionCatalog
	regions  atomic.Int32
	accounts atomic.Int32
}

func (c *discoveryCatalog) ProxmoxRegions(ctx context.Context) ([]backend.ProxmoxRegion, error) {
	c.regions.Add(1)
	return c.RegionCatalog.ProxmoxRegions(ctx)
}

func (c *discoveryCatalog) AWSAccounts(ctx context.Context) ([]backend.AWSAccount, error) {
	c.accounts.Add(1)
	return c.RegionCatalog.AWSAccounts(ctx)
}

func TestRegionDiscoveryReadsCatalogOnceAndBoundsConcurrency(t *testing.T) {
	_, _, caller := gatedService(t, backend.AllSupported{Kind: resource.RegionKindProxmox})
	regions := make([]backend.ProxmoxRegion, 24)
	for i := range regions {
		regions[i] = backend.ProxmoxRegion{Name: fmt.Sprintf("pve-test-%d", i), Endpoint: "https://region.example"}
	}
	catalog := &discoveryCatalog{RegionCatalog: backend.NewStaticRegions(regions, nil)}
	started, release := make(chan struct{}, 24), make(chan struct{})
	var active, calls atomic.Int32
	svc := New(Config{
		Regions: catalog,
		Discovery: func(ctx context.Context, region backend.ProxmoxRegion) (resource.RegionCapabilities, error) {
			calls.Add(1)
			if active.Add(1) > 8 {
				t.Error("more than eight simultaneous discovery reads")
			}
			defer active.Add(-1)
			if region.Endpoint != "https://region.example" || region.Kind != resource.RegionKindProxmox {
				t.Errorf("registered descriptor was lost: %+v", region)
			}
			started <- struct{}{}
			select {
			case <-release:
				return resource.RegionCapabilities{Region: region.Name, Kind: region.Kind}, nil
			case <-ctx.Done():
				return resource.RegionCapabilities{}, ctx.Err()
			}
		},
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		items, err := svc.Regions(t.Context(), caller)
		if err != nil || len(items) != len(regions) {
			t.Errorf("discovery: %+v %v", items, err)
		}
		for _, item := range items {
			if item.State != "available" {
				t.Errorf("unexpected discovery state: %+v", item)
			}
		}
	}()
	for range 8 {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			<-done
			t.Fatal("discovery did not start eight parallel reads")
		}
	}
	if calls.Load() != 8 || catalog.regions.Load() != 1 || catalog.accounts.Load() != 1 {
		t.Errorf("initial calls=%d, region lists=%d, account lists=%d",
			calls.Load(), catalog.regions.Load(), catalog.accounts.Load())
	}
	close(release)
	<-done
	if calls.Load() != 24 || catalog.regions.Load() != 1 || catalog.accounts.Load() != 1 {
		t.Fatalf("total calls=%d, region lists=%d, account lists=%d",
			calls.Load(), catalog.regions.Load(), catalog.accounts.Load())
	}
}
