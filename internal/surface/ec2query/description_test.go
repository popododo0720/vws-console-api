package ec2query

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// #594: an IpRanges description is stored and described, a second authorize
// of the same rule with another description is a duplicate, a revoke matches
// without it, and the EC2 limits apply.
func TestIngressRangeDescription(t *testing.T) {
	h, cred, now := harness(t)
	id := ingressGroup(t, h, cred, now)
	call := func(action, desc string) *httptest.ResponseRecorder {
		t.Helper()
		form := url.Values{
			"Action": {action}, "Version": {Version}, "GroupId": {id},
			"IpPermissions.1.IpProtocol": {"tcp"}, "IpPermissions.1.FromPort": {"22"}, "IpPermissions.1.ToPort": {"22"},
			"IpPermissions.1.IpRanges.1.CidrIp": {"10.0.0.0/16"},
		}
		if desc != "" {
			form.Set("IpPermissions.1.IpRanges.1.Description", desc)
		}
		return signed(t, h, cred, now, form.Encode())
	}
	if res := call("AuthorizeSecurityGroupIngress", "SSH from ops (bastion)"); res.Code != http.StatusOK {
		t.Fatalf("authorize %d %s", res.Code, res.Body)
	}
	if body := describedGroup(t, h, cred, now, id); !strings.Contains(body,
		"<cidrIp>10.0.0.0/16</cidrIp><description>SSH from ops (bastion)</description>") {
		t.Fatalf("description not described: %s", body)
	}
	if res := call("AuthorizeSecurityGroupIngress", "other"); res.Code != http.StatusBadRequest ||
		!strings.Contains(res.Body.String(), "<Code>InvalidPermission.Duplicate</Code>") {
		t.Fatalf("duplicate %d %s", res.Code, res.Body)
	}
	for _, bad := range []string{strings.Repeat("a", 256), "<script>", "caf\u00e9"} {
		res := call("AuthorizeSecurityGroupIngress", bad)
		if res.Code != http.StatusBadRequest ||
			!strings.Contains(res.Body.String(), "<Code>InvalidParameterValue</Code>") ||
			!strings.Contains(res.Body.String(), "Invalid rule description") {
			t.Fatalf("%q: %d %s", bad, res.Code, res.Body)
		}
	}
	if res := call("RevokeSecurityGroupIngress", ""); res.Code != http.StatusOK {
		t.Fatalf("revoke %d %s", res.Code, res.Body)
	}
	if body := describedGroup(t, h, cred, now, id); strings.Contains(body, "10.0.0.0/16") {
		t.Fatalf("revoke left the rule: %s", body)
	}
}
