package resource

import (
	"bytes"
	"testing"
)

func TestIsRuleID(t *testing.T) {
	for id, want := range map[string]bool{
		"sgr-0123456789abcdef0":  true,
		"sgr-01234567":           true,
		"sgr-0123456":            false,
		"sgr-0123456789abcdef01": false,
		"sgr-0123456789abcdefg":  false,
		"r00":                    false,
		"":                       false,
		"sg-0123456789abcdef0":   false,
	} {
		if got := IsRuleID(id); got != want {
			t.Errorf("IsRuleID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestMintRuleID(t *testing.T) {
	id, err := MintRuleID(bytes.NewReader(bytes.Repeat([]byte{0xab}, 9)))
	if err != nil || id != "sgr-ababababababababa" || !IsRuleID(id) {
		t.Fatalf("MintRuleID = %q, %v", id, err)
	}
	if _, err := MintRuleID(bytes.NewReader([]byte{1, 2})); CodeOf(err) != CodeInternal {
		t.Fatalf("short entropy: %v", err)
	}
}

func TestRulesOf(t *testing.T) {
	groupID, err := Parse[SecurityGroupID]("sg-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := Parse[AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	g := SecurityGroup{
		ID:      groupID,
		OwnerID: owner,
		Rules: []IngressRule{
			{Protocol: "tcp", FromPort: 22, ToPort: 22, Cidr: "10.0.0.0/16"},
			{Protocol: "udp", FromPort: 53, ToPort: 53, Cidr: "10.0.0.0/16"},
			{Protocol: "tcp", FromPort: 80, ToPort: 80, Cidr: "10.0.0.0/16"},
		},
		RuleIDs: []string{"sgr-00000000000000001", "r01"},
	}
	got := g.RulesOf([]IngressRule{
		{Protocol: "TCP", FromPort: 22, ToPort: 22, Cidr: "10.0.0.0/16"},   // normalized
		{Protocol: "udp", FromPort: 53, ToPort: 53, Cidr: "10.0.0.0/16"},   // legacy id: left out
		{Protocol: "tcp", FromPort: 80, ToPort: 80, Cidr: "10.0.0.0/16"},   // no id: left out
		{Protocol: "tcp", FromPort: 443, ToPort: 443, Cidr: "10.0.0.0/16"}, // not held
	})
	want := SecurityGroupRule{
		ID: "sgr-00000000000000001", GroupID: g.ID, OwnerID: g.OwnerID,
		Protocol: "tcp", FromPort: 22, ToPort: 22, CidrIpv4: "10.0.0.0/16",
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("RulesOf = %+v, want [%+v]", got, want)
	}
}
