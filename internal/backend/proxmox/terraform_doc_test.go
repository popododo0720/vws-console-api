package proxmox

import (
	"bufio"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

const terraformDoc = "../../../docs/terraform.md"

// TestTerraformDocMatchesCapabilities pins the action tables of
// docs/terraform.md to the capability document of a writable region.
func TestTerraformDocMatchesCapabilities(t *testing.T) {
	text := readDoc(t)
	w, _, _ := launchBackend(t, false)
	caps, err := w.b.RegionCapabilities(t.Context(), w.b.region)
	if err != nil {
		t.Fatal(err)
	}
	unsupported, served := map[string]string{}, map[string]string{}
	for key, c := range caps.Actions {
		if c.State == resource.ActionUnsupported {
			unsupported[key] = c.ReasonCode + "|" + c.Reason
			continue
		}
		served[key] = c.State.String() + "|" + c.ReasonCode + "|" + c.Reason
	}
	for name, want := range map[string]map[string]string{"unsupported": unsupported, "served": served} {
		got, err := capabilityTable(text, name)
		if err != nil {
			t.Fatal(err)
		}
		compareRows(t, name, got, want)
	}
}

// TestTerraformDocProviderBlocks checks the two provider aliases share the
// endpoint and, with VWS_TERRAFORM_PVE_MAIN naming vws-deploy's
// tests/compat/terraform-pve/main.tf, that the pve block has its settings.
func TestTerraformDocProviderBlocks(t *testing.T) {
	text := readDoc(t)
	blocks := map[string]map[string]string{}
	for _, alias := range []string{"pve", "aws"} {
		block, err := hclFlatten(fencedAfter(text, "<!-- terraform-provider: "+alias+" -->"))
		if err != nil {
			t.Fatalf("%s block: %v", alias, err)
		}
		if block["alias"] != `"`+alias+`"` {
			t.Fatalf("%s block alias = %q", alias, block["alias"])
		}
		blocks[alias] = block
	}
	if !strings.HasPrefix(blocks["pve"]["region"], `"pve-`) || blocks["pve"]["skip_region_validation"] != "true" ||
		strings.HasPrefix(blocks["aws"]["region"], `"pve-`) {
		t.Fatalf("regions pve=%v aws=%v", blocks["pve"], blocks["aws"])
	}
	endpoint := blocks["pve"]["endpoints.ec2"]
	for alias, block := range blocks {
		for _, service := range []string{"ec2", "sts", "iam"} {
			if got := block["endpoints."+service]; got != endpoint {
				t.Errorf("%s endpoints.%s = %q, want %q", alias, service, got, endpoint)
			}
		}
	}
	path := os.Getenv("VWS_TERRAFORM_PVE_MAIN")
	if path == "" {
		t.Skip("VWS_TERRAFORM_PVE_MAIN is not set; skipping the vws-deploy main.tf comparison")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := hclFlatten(string(raw))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if err := sameProviderSettings(blocks["pve"], profile); err != nil {
		t.Fatalf("docs pve block differs from %s: %v", path, err)
	}
	t.Logf("docs pve block has the %d provider settings of %s", len(profile), path)
}

// sameProviderSettings requires the doc block to set exactly the profile's
// settings plus alias, with the profile's literals and a literal for each
// profile variable.
func sameProviderSettings(doc, profile map[string]string) error {
	want := slices.Sorted(maps.Keys(profile))
	got := slices.DeleteFunc(slices.Sorted(maps.Keys(doc)), func(k string) bool { return k == "alias" })
	if !slices.Equal(got, want) {
		return fmt.Errorf("settings %v, want %v", got, want)
	}
	for _, key := range want {
		value := profile[key]
		if strings.HasPrefix(value, "var.") {
			if !strings.HasPrefix(doc[key], `"`) {
				return fmt.Errorf("%s = %s, want an example value for %s", key, doc[key], value)
			}
			continue
		}
		if doc[key] != value {
			return fmt.Errorf("%s = %s, want %s", key, doc[key], value)
		}
	}
	return nil
}

func readDoc(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(terraformDoc)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// capabilityTable returns the rows of the table after
// "<!-- capability-table: name -->", keyed by action, cells joined by "|".
func capabilityTable(text, name string) (map[string]string, error) {
	marker := "<!-- capability-table: " + name + " -->"
	_, after, ok := strings.Cut(text, marker)
	if !ok {
		return nil, fmt.Errorf("no %q in %s", marker, terraformDoc)
	}
	rows := map[string]string{}
	lines := bufio.NewScanner(strings.NewReader(after))
	seen := 0
	for lines.Scan() {
		line := strings.TrimSpace(lines.Text())
		if line == "" && seen == 0 {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			break
		}
		seen++
		if seen <= 2 {
			continue // header and separator
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.Trim(strings.TrimSpace(cells[i]), "`")
		}
		if _, dup := rows[cells[0]]; dup {
			return nil, fmt.Errorf("%s table lists %s twice", name, cells[0])
		}
		rows[cells[0]] = strings.Join(cells[1:], "|")
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s table has no rows", name)
	}
	return rows, nil
}

func compareRows(t *testing.T, name string, got, want map[string]string) {
	t.Helper()
	for _, key := range slices.Sorted(maps.Keys(want)) {
		if got[key] != want[key] {
			t.Errorf("%s table %s = %q, capability document has %q", name, key, got[key], want[key])
		}
	}
	for _, key := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[key]; !ok {
			t.Errorf("%s table lists %s, which the capability document does not", name, key)
		}
	}
}

// fencedAfter returns the first fenced code block after marker.
func fencedAfter(text, marker string) string {
	_, after, ok := strings.Cut(text, marker)
	if !ok {
		return ""
	}
	_, body, ok := strings.Cut(after, "```hcl\n")
	if !ok {
		return ""
	}
	body, _, _ = strings.Cut(body, "```")
	return body
}

// hclFlatten reads the first provider "aws" block of text into
// dotted-path settings; nested blocks and maps add a path element.
func hclFlatten(text string) (map[string]string, error) {
	out := map[string]string{}
	var path []string
	inside := false
	for line := range strings.Lines(text) {
		line = strings.TrimSpace(line)
		switch {
		case !inside:
			inside = line == `provider "aws" {`
		case line == "" || strings.HasPrefix(line, "#"):
		case line == "}":
			if len(path) == 0 {
				return out, nil
			}
			path = path[:len(path)-1]
		case strings.HasSuffix(line, "{"):
			name := strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(line, "{")), "=")
			path = append(path, strings.TrimSpace(name))
		default:
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return nil, fmt.Errorf("unreadable line %q", line)
			}
			key = strings.Trim(strings.TrimSpace(key), `"`)
			out[strings.Join(append(slices.Clone(path), key), ".")] = strings.TrimSpace(value)
		}
	}
	return nil, fmt.Errorf("no complete provider \"aws\" block")
}
