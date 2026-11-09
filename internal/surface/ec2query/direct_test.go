package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDirectNetworkWritesAreUnauthorizedOperation(t *testing.T) {
	h, cred, now := harness(t)
	send := func(f url.Values) string {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		if res.Code != http.StatusOK {
			t.Fatalf("%s %d %s", f.Get("Action"), res.Code, res.Body)
		}
		return res.Body.String()
	}
	inst := xmlText(t, send(launchForm(newSubnet(t, send), "direct-tags", nil)), "instanceId")
	for _, f := range []url.Values{
		{"Action": {"CreateSubnet"}, "VpcId": {"vpc-direct"}, "CidrBlock": {"192.168.200.0/25"}},
		{"Action": {"DeleteSubnet"}, "SubnetId": {"subnet-direct-prod"}},
		{
			"Action": {"CreateTags"}, "ResourceId.1": {inst}, "ResourceId.2": {"subnet-direct-prod"},
			"Tag.1.Key": {"owner"}, "Tag.1.Value": {"me"},
		},
		{"Action": {"CreateTags"}, "ResourceId.1": {"vpc-direct"}, "Tag.1.Key": {"owner"}, "Tag.1.Value": {"me"}},
		{"Action": {"DeleteVpc"}, "VpcId": {"vpc-direct"}},
		{"Action": {"CreateSecurityGroup"}, "VpcId": {"vpc-direct"}, "GroupName": {"web"}, "GroupDescription": {"web"}},
	} {
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "<Code>UnauthorizedOperation</Code>") {
			t.Errorf("%s %v: %d %s", f.Get("Action"), f, res.Code, res.Body)
		}
	}
	got := send(url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {inst}})
	if strings.Contains(got, "<key>owner</key>") {
		t.Fatalf("a refused CreateTags tagged the instance: %s", got)
	}
}
