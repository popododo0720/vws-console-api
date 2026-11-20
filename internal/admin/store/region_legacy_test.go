package store

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// TestRegionReadsLegacyPVEAPIURL pins the migration of records written before
// pveApiUrls: they load as a one-address list and the next write drops the old key.
func TestRegionReadsLegacyPVEAPIURL(t *testing.T) {
	ctx := t.Context()
	mem := NewMemory()
	legacy := `{"name":"pve-old-1","clusterName":"old","pveApiUrl":"https://10.0.0.1:8006","caPem":"ca",` +
		`"tokenId":"vws@pve!inventory","regionEndpoint":"https://region.example","zones":[]}`
	if _, err := mem.Create(ctx, "regions/pve-old-1", []byte(legacy)); err != nil {
		t.Fatal(err)
	}
	g := New(mem)
	got, err := g.Regions().Get(ctx, "pve-old-1")
	if err != nil || !reflect.DeepEqual(got.PVEAPIURLs, []string{"https://10.0.0.1:8006"}) || got.CAPEM != "ca" {
		t.Fatalf("legacy region: %+v %v", got, err)
	}
	if list, skipped, err := g.Regions().List(ctx); err != nil || len(skipped) != 0 || len(list) != 1 {
		t.Fatalf("list: %v %v %v", list, skipped, err)
	}
	if _, err := g.Regions().Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	entry, err := mem.Get(ctx, "regions/pve-old-1")
	if err != nil || strings.Contains(string(entry.Value), `"pveApiUrl"`) ||
		!strings.Contains(string(entry.Value), `"pveApiUrls":["https://10.0.0.1:8006"]`) {
		t.Fatalf("rewritten record: %s %v", entry.Value, err)
	}
	both := `{"name":"pve-new-1","pveApiUrl":"https://old:8006","pveApiUrls":["https://a:8006","https://b:8006"]}`
	var r Region
	want := []string{"https://a:8006", "https://b:8006"}
	if err := json.Unmarshal([]byte(both), &r); err != nil || !reflect.DeepEqual(r.PVEAPIURLs, want) {
		t.Fatalf("pveApiUrls must win: %+v %v", r, err)
	}
}
