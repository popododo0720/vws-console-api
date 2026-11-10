package ec2query

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

type ruleSetXML struct {
	Rules []struct {
		ID       string `xml:"securityGroupRuleId"`
		GroupID  string `xml:"groupId"`
		OwnerID  string `xml:"groupOwnerId"`
		IsEgress string `xml:"isEgress"`
		Protocol string `xml:"ipProtocol"`
		FromPort int    `xml:"fromPort"`
		ToPort   int    `xml:"toPort"`
		CidrIpv4 string `xml:"cidrIpv4"`
	} `xml:"securityGroupRuleSet>item"`
}

// #596: AuthorizeSecurityGroupIngress returns the rules it added, each with
// a stable sgr- id, and a retry names the same ids.
func TestAuthorizeIngressReturnsSecurityGroupRules(t *testing.T) {
	h, cred, now := harness(t)
	id := ingressGroup(t, h, cred, now)
	authorize := func(form url.Values) ruleSetXML {
		t.Helper()
		form.Set("Action", "AuthorizeSecurityGroupIngress")
		form.Set("Version", Version)
		form.Set("GroupId", id)
		res := signed(t, h, cred, now, form.Encode())
		var out ruleSetXML
		if res.Code != http.StatusOK || xml.Unmarshal(res.Body.Bytes(), &out) != nil {
			t.Fatalf("authorize %d %s", res.Code, res.Body)
		}
		return out
	}
	two := url.Values{
		"ClientToken":                {"tok-596"},
		"IpPermissions.1.IpProtocol": {"tcp"}, "IpPermissions.1.FromPort": {"22"}, "IpPermissions.1.ToPort": {"22"},
		"IpPermissions.1.IpRanges.1.CidrIp": {"10.0.0.0/16"},
		"IpPermissions.1.IpRanges.2.CidrIp": {"10.1.0.0/16"},
	}
	first := authorize(two)
	if len(first.Rules) != 2 {
		t.Fatalf("rules %+v", first.Rules)
	}
	for i, cidr := range []string{"10.0.0.0/16", "10.1.0.0/16"} {
		r := first.Rules[i]
		if !resource.IsRuleID(r.ID) || r.GroupID != id || r.OwnerID == "" || r.IsEgress != "false" ||
			r.Protocol != "tcp" || r.FromPort != 22 || r.ToPort != 22 || r.CidrIpv4 != cidr {
			t.Fatalf("rule %d: %+v", i, r)
		}
	}
	if first.Rules[0].ID == first.Rules[1].ID {
		t.Fatalf("one id for two rules: %+v", first.Rules)
	}
	if again := authorize(two); len(again.Rules) != 2 || again.Rules[0].ID != first.Rules[0].ID ||
		again.Rules[1].ID != first.Rules[1].ID {
		t.Fatalf("retry ids %+v, want %+v", again.Rules, first.Rules)
	}
	more := authorize(url.Values{
		"IpPermissions.1.IpProtocol": {"udp"}, "IpPermissions.1.FromPort": {"53"}, "IpPermissions.1.ToPort": {"53"},
		"IpPermissions.1.IpRanges.1.CidrIp": {"10.0.0.0/16"},
	})
	if len(more.Rules) != 1 || more.Rules[0].Protocol != "udp" ||
		more.Rules[0].ID == first.Rules[0].ID || more.Rules[0].ID == first.Rules[1].ID {
		t.Fatalf("only the added rule: %+v", more.Rules)
	}
}
