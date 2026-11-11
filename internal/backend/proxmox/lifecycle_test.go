package proxmox

import (
	"cmp"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestInstanceTransitionsMatchModel(t *testing.T) {
	spec, err := os.ReadFile("../../../docs/formal/instance.tla")
	if err != nil {
		t.Fatal(err)
	}
	want, err := parseInstanceTransitions(string(spec))
	if err != nil {
		t.Fatal(err)
	}
	got := InstanceTransitions()
	order := func(a, b [2]resource.InstanceState) int {
		if c := cmp.Compare(a[0], b[0]); c != 0 {
			return c
		}
		return cmp.Compare(a[1], b[1])
	}
	slices.SortFunc(got, order)
	slices.SortFunc(want, order)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Go lifecycle table = %v; model AllowedTransitions = %v", got, want)
	}
}

func parseInstanceTransitions(spec string) ([][2]resource.InstanceState, error) {
	_, table, ok := strings.Cut(spec, "AllowedTransitions == {\n")
	if !ok {
		return nil, fmt.Errorf("model has no AllowedTransitions table")
	}
	table, _, ok = strings.Cut(table, "\n}")
	if !ok {
		return nil, fmt.Errorf("model transition table is unterminated")
	}
	row := regexp.MustCompile(`^\s*<<"([a-z-]+)", "([a-z-]+)">>,?$`)
	edges := [][2]resource.InstanceState{}
	for _, line := range strings.Split(table, "\n") {
		match := row.FindStringSubmatch(line)
		if match == nil {
			return nil, fmt.Errorf("invalid model transition row %q", line)
		}
		from, fromOK := resource.ParseInstanceState(match[1])
		to, toOK := resource.ParseInstanceState(match[2])
		if !fromOK || !toOK {
			return nil, fmt.Errorf("unknown model state in %q", line)
		}
		edge := [2]resource.InstanceState{from, to}
		if slices.Contains(edges, edge) {
			return nil, fmt.Errorf("duplicate model transition %q", line)
		}
		edges = append(edges, edge)
	}
	return edges, nil
}

func TestInstanceTransitionTableBoundary(t *testing.T) {
	for _, spec := range []string{
		"",
		"AllowedTransitions == {\n",
		"AllowedTransitions == {\n}",
		"AllowedTransitions == {\n    <<\"unknown\", \"running\">>\n}",
		"AllowedTransitions == {\n    <<\"running\", \"stopped\">> garbage\n}",
		"AllowedTransitions == {\n    <<\"running\", \"stopped\">>,\n    <<\"running\", \"stopped\">>\n}",
	} {
		if _, err := parseInstanceTransitions(spec); err == nil {
			t.Errorf("accepted invalid table %q", spec)
		}
	}
	first := InstanceTransitions()
	first[0] = [2]resource.InstanceState{}
	if InstanceTransitions()[0][0] != resource.InstancePending {
		t.Fatal("one caller changed the shared lifecycle policy")
	}
	for _, edge := range InstanceTransitions() {
		if edge[0] == resource.InstanceTerminated || edge[0].String() == "" || edge[1].String() == "" {
			t.Errorf("invalid lifecycle boundary %v", edge)
		}
	}
}
