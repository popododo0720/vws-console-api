package store_test

import (
	"errors"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
)

func TestProjectMappingRefusesARegionReservedForDeletion(t *testing.T) {
	g := store.New(store.NewMemory())
	region, err := g.Regions().Create(t.Context(), store.Region{Name: "pve-test-1", ClusterName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	mapping := store.Project{Project: "111111111111", Pools: []store.ProjectPool{{Region: region.Name, Pool: "p"}}}
	region.Deleting = true
	if region, err = g.Regions().Update(t.Context(), region); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Projects().Put(t.Context(), mapping); !errors.Is(err, store.ErrRegionDeleting) {
		t.Fatalf("mapping a reserved region: %v", err)
	}
	region.Deleting = false
	if _, err := g.Regions().Update(t.Context(), region); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Projects().Put(t.Context(), mapping); err != nil {
		t.Fatalf("mapping after the reservation was released: %v", err)
	}
}
