// Package storetest is the admin store contract as tests. Every Backend runs
// it through a Registry.
package storetest

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
)

// Region returns a region to register.
func Region(name string) store.Region {
	return store.Region{
		Name:           name,
		ClusterName:    "seoul",
		PVEAPIURL:      "https://10.0.0.10:8006",
		TokenID:        "vws@pve!region",
		RegionEndpoint: "https://10.0.0.20:8443",
		Zones:          []store.Zone{{Letter: "a", Nodes: []string{"pve1", "pve2"}}},
	}
}

// Account returns an AWS account to register.
func Account(id string) store.AWSAccount {
	return store.AWSAccount{
		ID:             id,
		RoleARN:        "arn:aws:iam::" + id + ":role/vws",
		AllowedRegions: []string{"ap-northeast-2"},
	}
}

// Run checks the contract on the backend newBackend returns, which must be
// empty.
func Run(t *testing.T, newBackend func(t *testing.T) store.Backend) {
	t.Run("lifecycle", func(t *testing.T) { lifecycle(t, newBackend(t)) })
	t.Run("one writer wins", func(t *testing.T) { oneWriterWins(t, newBackend(t)) })
}

func oneWriterWins(t *testing.T, b store.Backend) {
	ctx := context.Background()
	accounts := store.New(b).AWSAccounts()
	base, err := accounts.Create(ctx, Account("123456789012"))
	if err != nil {
		t.Fatal(err)
	}
	const writers = 8
	errs := make(chan error, writers)
	for i := range writers {
		go func() {
			v := base
			v.AllowedRegions = []string{"ap-northeast-" + strconv.Itoa(i)}
			_, err := accounts.Update(ctx, v)
			errs <- err
		}()
	}
	won := 0
	for range writers {
		switch err := <-errs; {
		case err == nil:
			won++
		case !errors.Is(err, store.ErrConflict):
			t.Errorf("losing update: %v, want ErrConflict", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d updates at one version won, want 1", won)
	}
}

func lifecycle(t *testing.T, b store.Backend) {
	ctx := context.Background()
	regions := store.New(b).Regions()

	created, err := regions.Create(ctx, Region("pve-seoul-1"))
	if err != nil {
		t.Fatal(err)
	}
	if created.Version == 0 {
		t.Fatalf("created = %+v, want a version", created)
	}
	if _, err := regions.Create(ctx, Region("pve-seoul-1")); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second create: %v, want ErrExists", err)
	}

	got, err := regions.Get(ctx, "pve-seoul-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != created.Version || got.ClusterName != "seoul" ||
		!slices.Equal(got.Zones[0].Nodes, []string{"pve1", "pve2"}) {
		t.Fatalf("get = %+v, want %+v", got, created)
	}
	if _, err := regions.Get(ctx, "pve-busan-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get missing: %v, want ErrNotFound", err)
	}

	accounts := store.New(b).AWSAccounts()
	if _, err := accounts.Create(ctx, Account("123456789012")); err != nil {
		t.Fatal(err)
	}
	if _, err := regions.Create(ctx, Region("pve-busan-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Create(ctx, "regions/pve-corrupt", []byte("{")); err != nil {
		t.Fatal(err)
	}
	list, skipped, err := regions.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 1 || skipped[0].Key != "regions/pve-corrupt" {
		t.Fatalf("skipped = %+v, want the corrupt value reported", skipped)
	}
	if len(list) != 2 || list[0].Name != "pve-busan-1" || list[1].Name != "pve-seoul-1" {
		t.Fatalf("list = %+v, want the two regions in name order and no account", list)
	}

	stale := got
	got.ClusterName = "seoul-2"
	updated, err := regions.Update(ctx, got)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version == stale.Version {
		t.Fatal("update kept the version")
	}
	if _, err := regions.Update(ctx, stale); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("update at a stale version: %v, want ErrConflict", err)
	}
	if again, err := regions.Get(ctx, "pve-seoul-1"); err != nil || again.ClusterName != "seoul-2" {
		t.Fatalf("after a stale update: %+v, %v; want the first update kept", again, err)
	}
	if _, err := regions.Update(ctx, Region("pve-jeju-1")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update missing: %v, want ErrNotFound", err)
	}

	if err := regions.Delete(ctx, "pve-seoul-1", stale.Version); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("delete at a stale version: %v, want ErrConflict", err)
	}
	if err := regions.Delete(ctx, "pve-seoul-1", updated.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := regions.Get(ctx, "pve-seoul-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get after delete: %v, want ErrNotFound", err)
	}
	if err := regions.Delete(ctx, "pve-seoul-1", updated.Version); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second delete: %v, want ErrNotFound", err)
	}
	if _, err := regions.Create(ctx, Region("pve-seoul-1")); err != nil {
		t.Fatalf("create after delete: %v", err)
	}
	if _, err := regions.Get(ctx, "a/b"); err == nil {
		t.Fatal("a name with a slash was taken")
	}
}
