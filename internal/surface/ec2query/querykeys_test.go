package ec2query

import (
	"strconv"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestQueryKeyIndexesFollowTheirBounds(t *testing.T) {
	actions := []string{"ImportKeyPair", "DescribeInstanceAttribute"}
	for _, a := range resource.Actions() {
		actions = append(actions, a.String())
	}
	for _, a := range resource.ReadActions() {
		actions = append(actions, a.String())
	}
	for _, action := range actions {
		keys := queryKeys(action)
		for _, k := range keys {
			segs := strings.Split(k.pattern, ".")
			var slots []int
			for i, s := range segs {
				if s == "N" {
					slots = append(slots, i)
				}
			}
			if len(slots) != len(k.bounds) {
				t.Fatalf("%s %s: %d index segments, %d bounds", action, k.pattern, len(slots), len(k.bounds))
			}
			spell := func(slot int, index string) string {
				parts := append([]string(nil), segs...)
				for _, i := range slots {
					parts[i] = "1"
				}
				if slot >= 0 {
					parts[slots[slot]] = index
				}
				return strings.Join(parts, ".")
			}
			if base := spell(-1, ""); !acceptsKey(keys, base) || acceptsKey(keys, base+".x") {
				t.Errorf("%s %s: %q must be the only length taken", action, k.pattern, base)
			}
			for slot, bound := range k.bounds {
				for index, want := range map[string]bool{
					"1": true, strconv.Itoa(bound): true, strconv.Itoa(bound + 1): false, "0": false, "01": false, "+1": false,
				} {
					if key := spell(slot, index); acceptsKey(keys, key) != want {
						t.Errorf("%s %s: accepts %q = %v, want %v", action, k.pattern, key, !want, want)
					}
				}
			}
		}
	}
}
