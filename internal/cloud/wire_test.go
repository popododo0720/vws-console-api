package cloud

import (
	"os"
	"strings"
	"testing"
)

func TestKernelDoesNotNameIngressWireFields(t *testing.T) {
	banned := []string{"ipRanges", "ipv6Ranges", "userIdGroupPairs", "prefixListIds", "securityGroupRuleSet"}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		for _, word := range banned {
			if strings.Contains(text, word) {
				t.Errorf("%s contains %s", name, word)
			}
		}
	}
}
