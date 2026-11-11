package store

import (
	"errors"
	"testing"
	"time"
)

func TestClusterNameClaims(t *testing.T) {
	g := New(NewMemory())
	now := time.Unix(1_700_000_000, 0).UTC()
	stale := now.Add(ClaimGrace)
	if err := g.ClaimCluster(t.Context(), "lab", "pve-lab-1", now); err != nil {
		t.Fatal(err)
	}
	if err := g.ClaimCluster(t.Context(), "lab", "pve-other-1", now); !errors.Is(err, ErrExists) {
		t.Fatalf("a claim whose record is not written yet was taken: %v", err)
	}
	if err := g.ClaimCluster(t.Context(), "lab", "pve-lab-1", now); err != nil {
		t.Fatalf("owner re-claim: %v", err)
	}
	v, err := g.Regions().Create(t.Context(), Region{Name: "pve-lab-1", ClusterName: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.ClaimCluster(t.Context(), "lab", "pve-other-1", stale); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate cluster: %v", err)
	}
	if err := g.ReleaseCluster(t.Context(), "lab", "pve-other-1"); err != nil {
		t.Fatal(err)
	}
	if err := g.ClaimCluster(t.Context(), "lab", "pve-other-1", stale); !errors.Is(err, ErrExists) {
		t.Fatal("another region released the claim")
	}
	v.ClusterName = "renamed"
	if _, err := g.Regions().Update(t.Context(), v); err != nil {
		t.Fatal(err)
	}
	if err := g.ClaimCluster(t.Context(), "lab", "pve-other-1", now); !errors.Is(err, ErrExists) {
		t.Fatalf("claim of a renamed owner taken within the grace: %v", err)
	}
	if err := g.ClaimCluster(t.Context(), "lab", "pve-other-1", stale); err != nil {
		t.Fatalf("reclaim renamed owner: %v", err)
	}
	if err := g.ClaimCluster(t.Context(), "lab", "pve-third-1", stale.Add(ClaimGrace)); err != nil {
		t.Fatalf("reclaim missing owner: %v", err)
	}
	if err := g.ReleaseCluster(t.Context(), "lab", "pve-third-1"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "a/b", "../x", "lab\n", string(make([]byte, 64))} {
		if err := g.ClaimCluster(t.Context(), name, "pve-lab-1", now); !errors.Is(err, ErrInvalidClaim) {
			t.Fatalf("claim %q: %v", name, err)
		}
		if err := g.ReleaseCluster(t.Context(), name, "pve-lab-1"); !errors.Is(err, ErrInvalidClaim) {
			t.Fatalf("release %q: %v", name, err)
		}
	}
	rows, _, err := g.Regions().List(t.Context())
	if err != nil || len(rows) != 1 {
		t.Fatalf("index leaked into region list: %v", err)
	}
}
