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
			FromPort: new(22),
			ToPort:   new(22),
			IPRanges: []IPRange{{CidrIP: "10.0.0.0/16"}, {CidrIP: "10.1.0.0/16"}},
		},
		{Protocol: "udp", FromPort: new(53), ToPort: new(53), IPRanges: []IPRange{{CidrIP: "0.0.0.0/0"}}},
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
	base := IPPermission{Protocol: "tcp", FromPort: new(22), ToPort: new(22), IPRanges: []IPRange{{CidrIP: "10.0.0.0/16"}}}
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
	if _, err := IngressRules([]IPPermission{{Protocol: "tcp", FromPort: new(22), ToPort: new(22)}}); CodeOf(
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

// #219: an ICMP rule carries the type in FromPort and the code in ToPort.
// Each is 0 to 255 or -1 for all, and all types takes all codes.
func TestICMPTypeAndCodeFollowEC2(t *testing.T) {
	id, err := Parse[SecurityGroupID]("sg-01234567")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		typ, code int
		field     string
	}{
		{-1, -1, ""},
		{0, 0, ""},
		{8, 0, ""},
		{3, 4, ""},
		{8, -1, ""},
		{255, 255, ""},
		{-1, 0, "toPort"},
		{-2, -1, "fromPort"},
		{256, 0, "fromPort"},
		{0, 256, "toPort"},
		{0, -2, "toPort"},
	} {
		rule := IngressRule{Protocol: "1", FromPort: tc.typ, ToPort: tc.code, Cidr: "10.0.0.0/16"}
		got, err := (AuthorizeSecurityGroupIngressRequest{ID: id, Rules: []IngressRule{rule}}).Normalize()
		if tc.field == "" {
			want := IngressRule{Protocol: "icmp", FromPort: tc.typ, ToPort: tc.code, Cidr: "10.0.0.0/16"}
			if err != nil || got.Rules[0] != want {
				t.Errorf("%d/%d: %v %+v", tc.typ, tc.code, err, got.Rules)
			}
			continue
		}
		if e := AsError(err); CodeOf(err) != CodeInvalidArgument || IsMissingParameter(e) || e.Field != tc.field {
			t.Errorf("%d/%d: %v", tc.typ, tc.code, err)
		}
	}
}

// #219: EC2 requires a port range for icmp, so an ICMP permission that omits
// its type or its code is MissingParameter. A tcp permission keeps its old
// reading of an omitted port as 0.
func TestICMPPermissionNeedsTypeAndCode(t *testing.T) {
	ranges := []IPRange{{CidrIP: "10.0.0.0/16"}}
	for name, p := range map[string]IPPermission{
		"neither": {Protocol: "icmp", IPRanges: ranges},
		"no code": {Protocol: "icmp", FromPort: new(8), IPRanges: ranges},
		"no type": {Protocol: "ICMP", ToPort: new(0), IPRanges: ranges},
	} {
		if _, err := IngressRules([]IPPermission{p}); !IsMissingParameter(AsError(err)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	got, err := IngressRules([]IPPermission{{Protocol: "icmp", FromPort: new(0), ToPort: new(0), IPRanges: ranges}})
	if err != nil || got[0].FromPort != 0 || got[0].ToPort != 0 {
		t.Errorf("echo reply: %v %+v", err, got)
	}
	if _, err := IngressRules([]IPPermission{{Protocol: "tcp", IPRanges: ranges}}); err != nil {
		t.Errorf("tcp without ports: %v", err)
	}
}
