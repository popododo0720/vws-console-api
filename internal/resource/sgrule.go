package resource

import (
	"encoding/hex"
	"io"
	"strings"
)

// ruleIDPrefix starts every security group rule id, as in EC2.
const ruleIDPrefix = "sgr-"

// SecurityGroupRule is one inbound rule as EC2 SecurityGroupRule shows it,
// with its stable id.
type SecurityGroupRule struct {
	ID       string          `json:"securityGroupRuleId"`
	GroupID  SecurityGroupID `json:"groupId"`
	OwnerID  AccountID       `json:"groupOwnerId"`
	IsEgress bool            `json:"isEgress"`
	Protocol string          `json:"ipProtocol"`
	FromPort int             `json:"fromPort"`
	ToPort   int             `json:"toPort"`
	CidrIpv4 string          `json:"cidrIpv4"`
}

// IsRuleID reports whether s is a security group rule id: "sgr-" and 8 to 17
// hex digits.
func IsRuleID(s string) bool {
	rest, ok := strings.CutPrefix(s, ruleIDPrefix)
	if !ok || len(rest) < 8 || len(rest) > 17 {
		return false
	}
	for _, r := range rest {
		if !isHex(r) {
			return false
		}
	}
	return true
}

// MintRuleID creates a fresh rule id from entropy. Backends mint. Surfaces do
// not.
func MintRuleID(entropy io.Reader) (string, error) {
	var raw [9]byte
	if _, err := io.ReadFull(entropy, raw[:]); err != nil {
		return "", Internal(err)
	}
	return RuleIDFromHash(raw[:]), nil
}

// RuleIDFromHash makes a rule id from at least 9 bytes, for a backend that
// derives ids deterministically so a retry names the same rule.
func RuleIDFromHash(sum []byte) string {
	return ruleIDPrefix + hex.EncodeToString(sum)[:17]
}

// RulesOf returns the group's stored rules that match rules, with their ids,
// in the order of rules. A rule the group does not hold, or holds without an
// id, is left out.
func (g SecurityGroup) RulesOf(rules []IngressRule) []SecurityGroupRule {
	out := make([]SecurityGroupRule, 0, len(rules))
	for _, rule := range rules {
		canon, err := normalizeRule(rule)
		if err != nil {
			continue
		}
		for i, have := range g.Rules {
			if have != canon || i >= len(g.RuleIDs) || !IsRuleID(g.RuleIDs[i]) {
				continue
			}
			out = append(out, SecurityGroupRule{
				ID: g.RuleIDs[i], GroupID: g.ID, OwnerID: g.OwnerID,
				Protocol: have.Protocol, FromPort: have.FromPort, ToPort: have.ToPort, CidrIpv4: have.Cidr,
			})
			break
		}
	}
	return out
}
