package store

import (
	"context"
	"errors"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type failedProjectRead struct{ Backend }

func (failedProjectRead) Get(context.Context, string) (Entry, error) {
	return Entry{}, errors.New("registry unavailable")
}

func TestCatalogProjectPoolDefaultsAndRemapping(t *testing.T) {
	ctx := t.Context()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	memory := NewMemory()
	registry := New(memory)
	if _, err := registry.Regions().Create(ctx, Region{Name: "pve-test-1"}); err != nil {
		t.Fatal(err)
	}
	pools := registry.Catalog().(backend.ProjectPools)
	if pool, err := pools.ProjectPool(ctx, account, "pve-test-1"); err != nil || pool != account.String() {
		t.Fatalf("default pool: %q %v", pool, err)
	}
	for range 2 {
		mapping, err := registry.Projects().Get(ctx, account.String())
		switch {
		case errors.Is(err, ErrNotFound):
			mapping.Project = account.String()
		case err != nil:
			t.Fatal(err)
		default:
			got, err := registry.Catalog().(backend.ProjectPools).ProjectPool(ctx, account, "pve-test-1")
			if err != nil || got != "team-b" {
				t.Fatalf("mapping after reopen: %q %v", got, err)
			}
		}
		pools = registry.Catalog().(backend.ProjectPools)
		for _, pool := range []string{"team-a", "team-b"} {
			mapping.Pools = []ProjectPool{{Region: "pve-test-1", Pool: pool}}
			mapping, err = registry.Projects().Put(ctx, mapping)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := pools.ProjectPool(ctx, account, "pve-test-1"); err != nil || got != pool {
				t.Fatalf("remap: %q %v", got, err)
			}
			if got, err := pools.ProjectPool(ctx, account, "pve-other-1"); err != nil || got != account.String() {
				t.Fatalf("unmapped region: %q %v", got, err)
			}
		}
		registry = New(memory)
	}
	pools = New(failedProjectRead{memory}).Catalog().(backend.ProjectPools)
	if pool, err := pools.ProjectPool(ctx, account, "pve-test-1"); err == nil || pool != "" {
		t.Fatalf("failed registry read used default pool: %q %v", pool, err)
	}
}
