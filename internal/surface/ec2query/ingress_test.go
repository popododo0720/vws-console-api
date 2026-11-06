package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// ingressGroup creates a VPC and a security group and returns the group id.
func ingressGroup(t *testing.T, h http.Handler, cred sigv4.Credential, now time.Time) string {
	t.Helper()
	vpc := signed(t, h, cred, now, url.Values{
		"Action": {"CreateVpc"}, "Version": {Version}, "CidrBlock": {"10.7.0.0/16"},
	}.Encode())
	group := signed(t, h, cred, now, url.Values{
		"Action": {"CreateSecurityGroup"}, "Version": {Version},
		"GroupName": {"web"}, "GroupDescription": {"web"}, "VpcId": {xmlText(t, vpc.Body.String(), "vpcId")},
	}.Encode())
	if group.Code != http.StatusOK {
		t.Fatalf("group %d %s", group.Code, group.Body)
	}
	return xmlText(t, group.Body.String(), "groupId")
}

func describedGroup(t *testing.T, h http.Handler, cred sigv4.Credential, now time.Time, id string) string {
	t.Helper()
	described := signed(t, h, cred, now, url.Values{
		"Action": {"DescribeSecurityGroups"}, "Version": {Version}, "GroupId.1": {id},
	}.Encode())
	if described.Code != http.StatusOK {
		t.Fatalf("describe %d %s", described.Code, described.Body)
	}
	return described.Body.String()
}

// #217: one AuthorizeSecurityGroupIngress takes several permissions, each
// with several IpRanges, in any index order.
func TestAuthorizeIngressTakesSeveralPermissions(t *testing.T) {
	h, cred, now := harness(t)
	id := ingressGroup(t, h, cred, now)
	opened := signed(t, h, cred, now, url.Values{
		"Action": {"AuthorizeSecurityGroupIngress"}, "Version": {Version}, "GroupId": {id},
		"IpPermissions.1.IpProtocol": {"tcp"}, "IpPermissions.1.FromPort": {"22"}, "IpPermissions.1.ToPort": {"22"},
		"IpPermissions.1.IpRanges.1.CidrIp": {"10.0.0.0/16"},
		"IpPermissions.1.IpRanges.3.CidrIp": {"10.1.0.0/16"},
		"IpPermissions.2.IpProtocol": {
			"udp",
		}, "IpPermissions.2.FromPort": {"53"}, "IpPermissions.2.ToPort": {"53"},
		"IpPermissions.2.IpRanges.1.CidrIp": {"0.0.0.0/0"},
	}.Encode())
	if opened.Code != http.StatusOK || !strings.Contains(opened.Body.String(), "<return>true</return>") {
		t.Fatalf("authorize %d %s", opened.Code, opened.Body)
	}
	body := describedGroup(t, h, cred, now, id)
	for _, want := range []string{
		"<cidrIp>10.0.0.0/16</cidrIp>", "<cidrIp>10.1.0.0/16</cidrIp>", "<cidrIp>0.0.0.0/0</cidrIp>",
		"<ipProtocol>udp</ipProtocol>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
}

// #217: a source kind VWS cannot store is UnsupportedOperation, and no rule of
// the request is written.
func TestUnsupportedIngressSourceIsRefused(t *testing.T) {
	h, cred, now := harness(t)
	id := ingressGroup(t, h, cred, now)
	for _, extra := range []url.Values{
		{"IpPermissions.2.Ipv6Ranges.1.CidrIpv6": {"::/0"}},
		{"IpPermissions.2.Groups.1.GroupId": {id}},
		{"IpPermissions.2.PrefixListIds.1.PrefixListId": {"pl-12345678"}},
		{"IpPermissions.1.IpRanges.1.Description": {"ssh"}},
	} {
		form := url.Values{
			"Action": {"AuthorizeSecurityGroupIngress"}, "Version": {Version}, "GroupId": {id},
			"IpPermissions.1.IpProtocol": {"tcp"}, "IpPermissions.1.FromPort": {"22"}, "IpPermissions.1.ToPort": {"22"},
			"IpPermissions.1.IpRanges.1.CidrIp": {"10.0.0.0/16"},
			"IpPermissions.2.IpProtocol": {
				"tcp",
			}, "IpPermissions.2.FromPort": {"443"}, "IpPermissions.2.ToPort": {"443"},
		}
		for k, v := range extra {
			form[k] = v
		}
		res := signed(t, h, cred, now, form.Encode())
		if res.Code != http.StatusBadRequest ||
			!strings.Contains(res.Body.String(), "<Code>UnsupportedOperation</Code>") {
			t.Fatalf("%v: %d %s", extra, res.Code, res.Body)
		}
	}
	if body := describedGroup(t, h, cred, now, id); strings.Contains(body, "10.0.0.0/16") {
		t.Fatalf("a refused request wrote a rule: %s", body)
	}
}

// #217: AuthorizeSecurityGroupIngress is all or none. A rule the group has,
// or a rule named twice, refuses the whole request.
func TestAuthorizeIngressIsAllOrNothing(t *testing.T) {
	h, cred, now := harness(t)
	id := ingressGroup(t, h, cred, now)
	first := signed(t, h, cred, now, url.Values{
		"Action": {"AuthorizeSecurityGroupIngress"}, "Version": {Version}, "GroupId": {id},
		"IpProtocol": {"tcp"}, "FromPort": {"22"}, "ToPort": {"22"}, "CidrIp": {"10.0.0.0/16"},
	}.Encode())
	if first.Code != http.StatusOK {
		t.Fatalf("authorize %d %s", first.Code, first.Body)
	}
	for name, ranges := range map[string][]string{
		"existing":     {"10.9.0.0/16", "10.0.0.0/16"},
		"named twice":  {"10.9.0.0/16", "10.9.0.0/16"},
		"same network": {"10.9.0.0/16", "10.9.1.2/16"},
	} {
		form := url.Values{
			"Action": {"AuthorizeSecurityGroupIngress"}, "Version": {Version}, "GroupId": {id},
			"IpPermissions.1.IpProtocol": {"tcp"}, "IpPermissions.1.FromPort": {"22"}, "IpPermissions.1.ToPort": {"22"},
			"IpPermissions.1.IpRanges.1.CidrIp": {ranges[0]}, "IpPermissions.1.IpRanges.2.CidrIp": {ranges[1]},
		}
		res := signed(t, h, cred, now, form.Encode())
		if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "InvalidPermission.Duplicate") {
			t.Fatalf("%s: %d %s", name, res.Code, res.Body)
		}
	}
	if body := describedGroup(t, h, cred, now, id); strings.Contains(body, "10.9.0.0/16") {
		t.Fatalf("a refused request wrote a rule: %s", body)
	}
}

// #217: the top-level IpProtocol, FromPort, ToPort and CidrIp and the
// IpPermissions list cannot be mixed, and a request needs one of them.
func TestAuthorizeIngressRefusesAmbiguousForms(t *testing.T) {
	h, cred, now := harness(t)
	id := ingressGroup(t, h, cred, now)
	mixed := signed(t, h, cred, now, url.Values{
		"Action": {"AuthorizeSecurityGroupIngress"}, "Version": {Version}, "GroupId": {id},
		"IpProtocol": {"tcp"}, "FromPort": {"22"}, "ToPort": {"22"}, "CidrIp": {"10.0.0.0/16"},
		"IpPermissions.1.IpProtocol": {"udp"}, "IpPermissions.1.IpRanges.1.CidrIp": {"10.1.0.0/16"},
	}.Encode())
	if mixed.Code != http.StatusBadRequest || !strings.Contains(mixed.Body.String(), "InvalidParameterCombination") {
		t.Fatalf("mixed %d %s", mixed.Code, mixed.Body)
	}
	empty := signed(t, h, cred, now, url.Values{
		"Action": {"AuthorizeSecurityGroupIngress"}, "Version": {Version}, "GroupId": {id},
	}.Encode())
	if empty.Code != http.StatusBadRequest || !strings.Contains(empty.Body.String(), "MissingParameter") {
		t.Fatalf("empty %d %s", empty.Code, empty.Body)
	}
}

// #217: one request adds at most resource.MaxIngressRules rules.
func TestAuthorizeIngressBoundsTheRuleCount(t *testing.T) {
	h, cred, now := harness(t)
	id := ingressGroup(t, h, cred, now)
	form := url.Values{"Action": {"AuthorizeSecurityGroupIngress"}, "Version": {Version}, "GroupId": {id}}
	for n := 1; n <= 2; n++ {
		p := "IpPermissions." + itoa(n) + "."
		form.Set(p+"IpProtocol", "tcp")
		form.Set(p+"FromPort", itoa(n))
		form.Set(p+"ToPort", itoa(n))
		for m := 1; m <= 31; m++ {
			form.Set(p+"IpRanges."+itoa(m)+".CidrIp", "10."+itoa(m)+".0.0/16")
		}
	}
	res := signed(t, h, cred, now, form.Encode())
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "InvalidParameterValue") {
		t.Fatalf("62 rules %d %s", res.Code, res.Body)
	}
	form.Del("IpPermissions.2.IpRanges.31.CidrIp")
	form.Del("IpPermissions.2.IpRanges.30.CidrIp")
	if res := signed(t, h, cred, now, form.Encode()); res.Code != http.StatusOK {
		t.Fatalf("60 rules %d %s", res.Code, res.Body)
	}
}
