package resource

import (
	"strings"
	"testing"
)

// #217: IngressRules turns each IPv4 range of each permission into one rule,
// in request order.
func TestIngressRulesFlattensPermissions(t *testing.T) {
	got, err := IngressRules([]IPPermission{
		{
			Protocol: "tcp",
			FromPort: 22,
			ToPort:   22,
			IPRanges: []IPRange{{CidrIP: "10.0.0.0/16"}, {CidrIP: "10.1.0.0/16"}},
		},
		{Protocol: "udp", FromPort: 53, ToPort: 53, IPRanges: []IPRange{{CidrIP: "0.0.0.0/0"}}},
	})
	want := []IngressRule{
		{Protocol: "tcp", FromPort: 22, ToPort: 22, Cidr: "10.0.0.0/16"},
		{Protocol: "tcp", FromPort: 22, ToPort: 22, Cidr: "10.1.0.0/16"},
		{Protocol: "udp", FromPort: 53, ToPort: 53, Cidr: "0.0.0.0/0"},
	}
	if err != nil || len(got) != len(want) {
		t.Fatalf("%v %+v", err, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rule %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// #217: a source VWS cannot store is refused as Unsupported, never dropped.
func TestIngressRulesRefusesWhatItCannotStore(t *testing.T) {
	base := IPPermission{Protocol: "tcp", FromPort: 22, ToPort: 22, IPRanges: []IPRange{{CidrIP: "10.0.0.0/16"}}}
	cases := map[string]func(*IPPermission){
		"ipv6Ranges":       func(p *IPPermission) { p.IPv6Ranges = []IPv6Range{{CidrIPv6: "::/0"}} },
		"userIdGroupPairs": func(p *IPPermission) { p.UserIDGroupPairs = []UserIDGroupPair{{GroupID: "sg-01234567"}} },
		"prefixListIds":    func(p *IPPermission) { p.PrefixListIDs = []PrefixListID{{PrefixListID: "pl-12345678"}} },
		"description":      func(p *IPPermission) { p.IPRanges = []IPRange{{CidrIP: "10.0.0.0/16", Description: "ssh"}} },
	}
	for field, edit := range cases {
		p := base
		edit(&p)
		_, err := IngressRules([]IPPermission{base, p})
		if e := AsError(err); !IsUnsupported(e) || e.Field != field {
			t.Errorf("%s: %v", field, err)
		}
	}
	if _, err := IngressRules([]IPPermission{{Protocol: "tcp", FromPort: 22, ToPort: 22}}); CodeOf(
		err,
	) != CodeInvalidArgument {
		t.Errorf("no range: %v", err)
	}
}

func TestAuthorizeIngressNormalize(t *testing.T) {
	id, err := Parse[SecurityGroupID]("sg-01234567")
	if err != nil {
		t.Fatal(err)
	}
	rule := IngressRule{Protocol: "tcp", FromPort: 22, ToPort: 22, Cidr: "10.0.0.0/16"}
	if _, err := (AuthorizeSecurityGroupIngressRequest{ID: id}).Normalize(); !IsMissingParameter(AsError(err)) {
		t.Errorf("no rules: %v", err)
	}
	same := rule
	same.Cidr = "10.0.1.2/16"
	_, err = (AuthorizeSecurityGroupIngressRequest{ID: id, Rules: []IngressRule{rule, same}}).Normalize()
	if !IsDuplicatePermission(err) {
		t.Errorf("one network twice: %v", err)
	}
	many := make([]IngressRule, MaxIngressRules+1)
	for i := range many {
		many[i] = IngressRule{Protocol: "tcp", FromPort: i, ToPort: i, Cidr: "10.0.0.0/16"}
	}
	if _, err := (AuthorizeSecurityGroupIngressRequest{ID: id, Rules: many}).Normalize(); CodeOf(
		err,
	) != CodeInvalidArgument ||
		!strings.Contains(err.Error(), "at most") {
		t.Errorf("too many: %v", err)
	}
	got, err := (AuthorizeSecurityGroupIngressRequest{ID: id, Rules: many[:MaxIngressRules]}).Normalize()
	if err != nil || len(got.Rules) != MaxIngressRules {
		t.Errorf("at the bound: %v %d", err, len(got.Rules))
	}
}
