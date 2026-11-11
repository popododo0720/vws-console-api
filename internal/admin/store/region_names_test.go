package store

import (
	"errors"
	"testing"
)

func TestClusterNameClaims(t *testing.T) {
	g := New(NewMemory())
	if err := g.ClaimCluster(t.Context(), "lab", "pve-lab-1"); err != nil {
		t.Fatal(err)
	}
	v, err := g.Regions().Create(t.Context(), Region{Name: "pve-lab-1", ClusterName: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.ClaimCluster(t.Context(), "lab", "pve-other-1"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate cluster: %v", err)
	}
	if err := g.ReleaseCluster(t.Context(), "lab", "pve-other-1"); err != nil {
		t.Fatal(err)
	}
	if err := g.ClaimCluster(t.Context(), "lab", "pve-other-1"); !errors.Is(err, ErrExists) {
		t.Fatal("another region released the claim")
	}
	v.ClusterName = "renamed"
	if _, err := g.Regions().Update(t.Context(), v); err != nil {
		t.Fatal(err)
	}
	if err := g.ClaimCluster(t.Context(), "lab", "pve-other-1"); err != nil {
		t.Fatalf("reclaim renamed owner: %v", err)
	}
	if err := g.ClaimCluster(t.Context(), "lab", "pve-third-1"); err != nil {
		t.Fatalf("reclaim missing owner: %v", err)
	}
	if err := g.ReleaseCluster(t.Context(), "lab", "pve-third-1"); err != nil {
		t.Fatal(err)
	}
	rows, _, err := g.Regions().List(t.Context())
	if err != nil || len(rows) != 1 {
		t.Fatalf("index leaked into region list: %v", err)
	}
}
