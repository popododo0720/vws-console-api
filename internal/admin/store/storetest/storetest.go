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
	t.Run("RGW credentials", func(t *testing.T) { rgwCredentials(t, newBackend(t)) })
	t.Run("one writer wins", func(t *testing.T) { oneWriterWins(t, newBackend(t)) })
	t.Run("project pool claims", func(t *testing.T) { projectClaims(t, newBackend(t)) })
	t.Run("project list", func(t *testing.T) { projectList(t, newBackend(t)) })
	t.Run("project concurrency", func(t *testing.T) { projectConcurrency(t, newBackend(t)) })
	t.Run("project interrupted write", func(t *testing.T) { projectInterruptedWrite(t, newBackend(t)) })
	t.Run("project transaction limit", func(t *testing.T) { projectTransactionLimit(t, newBackend(t)) })
}

func projectList(t *testing.T, b store.Backend) {
	ctx := t.Context()
	projects := store.New(b).Projects()
	items, skipped, err := projects.List(ctx)
	if err != nil || items == nil || len(items) != 0 || len(skipped) != 0 {
		t.Fatalf("empty list: %+v %+v %v", items, skipped, err)
	}
	second, err := projects.Put(ctx, store.Project{
		Project:     "222222222222",
		Pools:       []store.ProjectPool{{Region: "pve-test-1", Pool: "shared"}},
		AWSAccounts: []string{"333333333333"},
	})
	if err != nil {
		t.Fatal(err)
	}
	version, err := b.Create(ctx, "projects/111111111111", []byte(`{"project":"111111111111"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Create(ctx, "projects/corrupt", []byte("{")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		items, skipped, err = store.New(b).Projects().List(ctx)
		if err != nil || len(items) != 2 || len(skipped) != 1 || skipped[0].Key != "projects/corrupt" {
			t.Fatalf("list mappings without pool claims: %+v %+v %v", items, skipped, err)
		}
		if items[0].Project != "111111111111" || items[0].Version != version ||
			items[0].Pools == nil || len(items[0].Pools) != 0 ||
			items[0].AWSAccounts == nil || len(items[0].AWSAccounts) != 0 ||
			items[1].Project != second.Project || items[1].Version != second.Version ||
			!slices.Equal(items[1].Pools, second.Pools) || !slices.Equal(items[1].AWSAccounts, second.AWSAccounts) {
			t.Fatalf("sorted mappings after registry recreation: %+v", items)
		}
	}
}

func projectTransactionLimit(t *testing.T, b store.Backend) {
	v := store.Project{Project: "111111111111"}
	for i := range 32 {
		v.Pools = append(v.Pools, store.ProjectPool{Region: "pve-site-" + strconv.Itoa(i), Pool: "old"})
	}
	projects := store.New(b).Projects()
	v, err := projects.Put(t.Context(), v)
	if err != nil {
		t.Fatal(err)
	}
	for i := range v.Pools {
		v.Pools[i].Pool = "new"
	}
	v, err = projects.Put(t.Context(), v)
	if err != nil {
		t.Fatalf("largest replacement transaction: %v", err)
	}
	v.Pools = append(v.Pools, store.ProjectPool{Region: "pve-extra-1", Pool: "overflow"})
	if _, err := projects.Put(t.Context(), v); err == nil {
		t.Fatal("oversized transaction accepted")
	}
	claims, err := b.List(t.Context(), "project-pools/")
	if err != nil || len(claims) != 32 {
		t.Fatalf("boundary update claims: count=%d err=%v", len(claims), err)
	}
}

func projectClaims(t *testing.T, b store.Backend) {
	ctx := t.Context()
	projects := store.New(b).Projects()
	pool := store.ProjectPool{Region: "pve-test-1", Pool: "shared"}
	first, err := projects.Put(ctx, store.Project{Project: "111111111111", Pools: []store.ProjectPool{pool}})
	if err != nil || first.Version == 0 {
		t.Fatalf("create mapping: %+v %v", first, err)
	}
	again, err := store.New(b).Projects().Put(ctx, first)
	if err != nil || again.Version != first.Version {
		t.Fatalf("idempotent retry after registry recreation: %+v %v", again, err)
	}
	second := store.Project{Project: "222222222222", Pools: []store.ProjectPool{pool}}
	if _, err := projects.Put(ctx, second); !errors.Is(err, store.ErrExists) {
		t.Fatalf("exclusive pool: %v", err)
	}
	otherRegion := second
	otherRegion.Pools = []store.ProjectPool{{Region: "pve-other-1", Pool: pool.Pool}}
	if _, err := projects.Put(ctx, otherRegion); err != nil {
		t.Fatalf("same pool name in another region: %v", err)
	}
	first.Pools = []store.ProjectPool{{Region: pool.Region, Pool: "replacement"}}
	updated, err := projects.Put(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	stale := first
	stale.Pools = []store.ProjectPool{{Region: pool.Region, Pool: "must-not-leak"}}
	if _, err := projects.Put(ctx, stale); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	if _, err := b.Get(ctx, "project-pools/"+pool.Region+"/must-not-leak"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("failed CAS leaked a claim: %v", err)
	}
	second.Project = "333333333333"
	if _, err := projects.Put(ctx, second); err != nil {
		t.Fatalf("released pool could not move: %v", err)
	}
	got, err := projects.Get(ctx, first.Project)
	if err != nil || got.Version != updated.Version || !slices.Equal(got.Pools, updated.Pools) {
		t.Fatalf("stored mapping changed: %+v %v", got, err)
	}
}

func projectConcurrency(t *testing.T, b store.Backend) {
	const writers = 8
	ctx := t.Context()
	results := make(chan error, writers)
	start := make(chan struct{})
	for i := range writers {
		go func() {
			<-start
			_, err := store.New(b).Projects().Put(ctx, store.Project{
				Project: strconv.FormatInt(111111111111+int64(i), 10),
				Pools:   []store.ProjectPool{{Region: "pve-test-1", Pool: "race"}},
			})
			results <- err
		}()
	}
	close(start)
	winners := 0
	for range writers {
		err := <-results
		switch {
		case err == nil:
			winners++
		case !errors.Is(err, store.ErrExists) && !errors.Is(err, store.ErrConflict):
			t.Fatalf("race returned %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("%d projects acquired one pool", winners)
	}
	base, err := store.New(b).Projects().Put(ctx, store.Project{Project: "999999999999"})
	if err != nil {
		t.Fatal(err)
	}
	for i := range writers {
		go func() {
			v := base
			v.Pools = []store.ProjectPool{{Region: "pve-test-1", Pool: "writer-" + strconv.Itoa(i)}}
			_, err := store.New(b).Projects().Put(ctx, v)
			results <- err
		}()
	}
	winners = 0
	for range writers {
		err := <-results
		if err == nil {
			winners++
		} else if !errors.Is(err, store.ErrConflict) {
			t.Fatalf("same-project race: %v", err)
		}
	}
	claims, err := b.List(ctx, "project-pools/")
	if err != nil || winners != 1 || len(claims) != 2 {
		t.Fatalf("race leaked claims: winners=%d claims=%d err=%v", winners, len(claims), err)
	}
}

type interruptedProjectStore struct {
	store.Backend
	after bool
}

func (b interruptedProjectStore) Swap(
	ctx context.Context, checks, puts []store.Entry, deletes []string,
) (store.Version, error) {
	if b.after {
		if _, err := b.Backend.Swap(ctx, checks, puts, deletes); err != nil {
			return 0, err
		}
	}
	return 0, context.Canceled
}

func projectInterruptedWrite(t *testing.T, b store.Backend) {
	ctx := t.Context()
	v := store.Project{
		Project: "111111111111", Pools: []store.ProjectPool{{Region: "pve-test-1", Pool: "crash"}},
	}
	if _, err := store.New(interruptedProjectStore{Backend: b}).Projects().Put(ctx, v); err == nil {
		t.Fatal("interrupted write succeeded")
	}
	claims, err := b.List(ctx, "project-pools/")
	if err != nil || len(claims) != 0 {
		t.Fatalf("interrupted write left claims: %+v %v", claims, err)
	}
	if _, err := store.New(interruptedProjectStore{Backend: b, after: true}).Projects().Put(ctx, v); err == nil {
		t.Fatal("lost response succeeded")
	}
	projects := store.New(b).Projects()
	stored, err := projects.Get(ctx, v.Project)
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := projects.Put(ctx, stored); err != nil || retry.Version != stored.Version {
		t.Fatalf("retry after committed but lost response: %+v %v", retry, err)
	}
	v.Project = "222222222222"
	if _, err := projects.Put(ctx, v); !errors.Is(err, store.ErrExists) {
		t.Fatalf("lost response lost the exclusive claim: %v", err)
	}
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
