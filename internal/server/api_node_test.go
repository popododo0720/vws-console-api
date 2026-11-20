package server

import (
	"strings"
	"testing"
)

func TestRegionAPINodeGaugeTracksConnectedNode(t *testing.T) {
	node := "pve1"
	m := NewMetrics()
	m.regionAPINode = func() string { return node }
	for _, current := range []string{"pve1", "pve2", ""} {
		node = current
		var out strings.Builder
		if _, err := m.WriteTo(&out); err != nil {
			t.Fatal(err)
		}
		text := out.String()
		if strings.Contains(text, "leader") {
			t.Fatalf("metrics still name a leader: %s", text)
		}
		for _, candidate := range []string{"pve1", "pve2"} {
			series := `vws_region_api_node{node="` + candidate + `"} 1`
			if strings.Contains(text, series) != (candidate == current) {
				t.Fatalf("current=%q metrics=%s", current, text)
			}
		}
	}
}
