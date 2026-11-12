package ec2query

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestServedActionsFollowTheModel(t *testing.T) {
	data, err := os.ReadFile("served_actions.txt")
	if err != nil {
		t.Fatal(err)
	}
	served := strings.Fields(string(data))
	operations := modelOperations()
	if !slices.IsSorted(served) || len(slices.Compact(slices.Clone(served))) != len(served) {
		t.Fatal("served actions must be sorted and unique")
	}
	var generated []string
	for _, action := range modelActions() {
		generated = append(generated, action.name)
	}
	if !slices.Equal(served, generated) {
		t.Error("served actions differ from generated cases; run go generate")
	}
	for _, action := range served {
		if !slices.Contains(operations, action) {
			t.Errorf("served action %s is absent from the model", action)
		}
	}
	for _, action := range operations {
		t.Run(action, func(t *testing.T) {
			h, cred, now := harness(t)
			rec := signed(t, h, cred, now, url.Values{"Action": {action}, "Version": {Version}}.Encode())
			if slices.Contains(served, action) && rec.Code == http.StatusOK {
				return
			}
			body := ec2ErrorXML(t, rec.Body.Bytes())
			if slices.Contains(served, action) {
				if body.Code == "InvalidAction" {
					t.Fatalf("served action was not dispatched: %d %s", rec.Code, rec.Body)
				}
				return
			}
			if rec.Code != http.StatusBadRequest || body.Code != "InvalidAction" || body.Message != action {
				t.Fatalf("unserved action: %d %s; want 400 InvalidAction with message %q", rec.Code, rec.Body, action)
			}
		})
	}
}

func TestQueryKeysFollowTheModel(t *testing.T) {
	// Keys built at runtime from values outside literals need the data-driven filter in part 2.
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	keyPattern := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z0-9]+)*$`)
	vocabulary := map[string]bool{}
	literalKeys := map[string]bool{}
	fset := token.NewFileSet()
	for _, entry := range files {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, entry.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse query source %s: %v", entry.Name(), err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatalf("decode query source literal in %s: %v", entry.Name(), err)
			}
			if keyPattern.MatchString(value) {
				normalized := concreteModelKey(value)
				for _, key := range []string{value, value + ".1", normalized, normalized + ".1"} {
					literalKeys[key] = true
				}
			}
			for _, word := range strings.Split(value, ".") {
				if keyPattern.MatchString(word) {
					vocabulary[word] = true
				}
			}
			return true
		})
	}
	words := slices.Sorted(maps.Keys(vocabulary))
	// Bogus is an unknown-key control outside the finite union of model keys.
	candidates := maps.Clone(literalKeys)
	candidates["Bogus"] = true
	for _, word := range words {
		candidates[word] = true
		candidates[word+".1"] = true
	}
	delete(candidates, "Action")
	delete(candidates, "Version")
	for _, action := range modelActions() {
		for _, key := range action.keys {
			candidates[concreteModelKey(key.path)] = true
		}
	}
	// Probe SDK spellings even before they have a deviation entry.
	for _, key := range []string{
		"dryRun", "maxResults", "nextToken", "includeAllInstances", "includeManagedResources",
		"includeUnsupportedInRegion", "OwnerId.1",
	} {
		candidates[key] = true
	}
	deviations := modelDeviations()
	for _, d := range deviations {
		candidates[d.key] = true
	}
	for _, action := range modelActions() {
		t.Run(action.name, func(t *testing.T) {
			actionCandidates := maps.Clone(candidates)
			keys := map[string]bool{}
			required := map[string]bool{}
			prefixes := map[string]bool{}
			for _, key := range action.keys {
				path := concreteModelKey(key.path)
				keys[path] = true
				required[path] = key.required
				if last := strings.LastIndexByte(path, '.'); last >= 0 {
					prefixes[path[:last+1]] = true
				}
			}
			for _, prefix := range slices.Sorted(maps.Keys(prefixes)) {
				for _, word := range words {
					actionCandidates[prefix+word] = true
				}
			}
			allowed := map[string]string{}
			for _, d := range deviations {
				if d.action != action.name {
					continue
				}
				if strings.TrimSpace(d.reason) == "" {
					t.Errorf("deviation %s has no reason", d.key)
				}
				path := concreteModelKey(d.key)
				if _, exists := allowed[path]; exists {
					t.Errorf("duplicate deviation %s", d.key)
				}
				allowed[path] = d.reason
				// A model key needs a deviation only when VWS refuses a required member.
				accepted := modelKeyAccepted(t, action.name, d.key)
				if (keys[path] && accepted) || (!keys[path] && !accepted) || (keys[path] && !required[path]) {
					t.Errorf("stale deviation %s: %s", d.key, d.reason)
				}
			}
			for _, key := range slices.Sorted(maps.Keys(actionCandidates)) {
				path := concreteModelKey(key)
				if !keys[path] && modelKeyAccepted(t, action.name, key) && allowed[path] == "" {
					t.Errorf("accepted key %s is absent from model and deviations", key)
				}
			}
		})
	}
	for _, d := range deviations {
		if !slices.ContainsFunc(modelActions(), func(a modelAction) bool { return a.name == d.action }) {
			t.Errorf("deviation names unserved action %s", d.action)
		}
	}
}

func TestRequiredModelKeysAreAccepted(t *testing.T) {
	for _, action := range modelActions() {
		t.Run(action.name, func(t *testing.T) {
			for _, key := range action.keys {
				if !key.required {
					continue
				}
				path := concreteModelKey(key.path)
				if modelKeyAccepted(t, action.name, path) {
					continue
				}
				if !slices.ContainsFunc(modelDeviations(), func(d modelDeviation) bool {
					return d.action == action.name && d.key == path && strings.TrimSpace(d.reason) != ""
				}) {
					t.Errorf("required model key %s is refused", path)
				}
			}
		})
	}
}

func concreteModelKey(path string) string {
	parts := strings.Split(path, ".")
	for i, part := range parts {
		if part == "N" || (part != "" && strings.Trim(part, "0123456789") == "") {
			parts[i] = "1"
		}
	}
	return strings.Join(parts, ".")
}

func modelKeyAccepted(t *testing.T, action, key string) bool {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	r.Form = url.Values{"Action": {action}, "Version": {Version}, key: {"probe"}}
	return rejectUnknown(r, action) == nil
}
