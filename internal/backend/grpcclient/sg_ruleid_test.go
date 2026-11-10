package grpcclient

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestRuleIDKeepsMigratesAndMints(t *testing.T) {
	groupID, err := resource.Parse[resource.SecurityGroupID]("sg-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	ssh := resource.IngressRule{Protocol: "tcp", FromPort: 22, ToPort: 22, Cidr: "10.0.0.0/16"}
	dns := resource.IngressRule{Protocol: "udp", FromPort: 53, ToPort: 53, Cidr: "10.0.0.0/16"}
	current := resource.SecurityGroup{
		ID: groupID, Rules: []resource.IngressRule{ssh, dns},
		RuleIDs: []string{"sgr-00000000000000001", "r01"},
	}
	if got := ruleID(current, ssh, "k1", 0); got != "sgr-00000000000000001" {
		t.Fatalf("kept id = %q", got)
	}
	legacy := ruleID(current, dns, "k1", 1)
	if !resource.IsRuleID(legacy) || legacy != ruleID(current, dns, "k2", 7) {
		t.Fatalf("legacy id %q is not a stable sgr- id", legacy)
	}
	// New rules: one id per request and position, so a retry names the same
	// rules, and more than 256 rules still get distinct ids.
	seen := map[string]bool{legacy: true, "sgr-00000000000000001": true}
	for i := range 300 {
		rule := resource.IngressRule{Protocol: "tcp", FromPort: 1000 + i, ToPort: 1000 + i, Cidr: "10.0.0.0/16"}
		id := ruleID(current, rule, "k1", i)
		if !resource.IsRuleID(id) || seen[id] || id != ruleID(current, rule, "k1", i) {
			t.Fatalf("rule %d id %q", i, id)
		}
		seen[id] = true
	}
	if ruleID(current, resource.IngressRule{}, "k1", 0) == ruleID(current, resource.IngressRule{}, "k2", 0) {
		t.Fatal("two requests minted the same id")
	}
}
