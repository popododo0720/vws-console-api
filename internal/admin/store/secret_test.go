package store_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
)

func TestSecretMetadataNeverStoresTheValue(t *testing.T) {
	if got := store.DescribeSecret("hello"); !got.Set || got.Fingerprint != "2cf24dba" {
		t.Fatalf("SHA-256 prefix: %+v", got)
	}
	if got := store.DescribeSecret(""); got.Set || got.Fingerprint != "" {
		t.Fatalf("empty secret: %+v", got)
	}
	b := store.NewMemory()
	g := store.New(b)
	if _, err := g.Regions().Create(t.Context(), store.Region{
		Name: "pve-lab-1", TokenSecret: store.DescribeSecret("pve-private-value"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.AWSAccounts().Create(t.Context(), store.AWSAccount{
		ID: "123456789012", ExternalID: store.DescribeSecret("aws-private-value"),
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := b.List(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !json.Valid(entry.Value) || strings.Contains(string(entry.Value), "private-value") {
			t.Fatalf("invalid or secret-bearing record: %s", entry.Key)
		}
	}
	region, err := g.Regions().Get(t.Context(), "pve-lab-1")
	if err != nil {
		t.Fatal(err)
	}
	if region.TokenSecret != store.DescribeSecret("pve-private-value") {
		t.Fatal("metadata lost after reload")
	}
}
