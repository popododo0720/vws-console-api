package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDescribeInstancesReturnsTagSetAndOwner(t *testing.T) {
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
	vpc := send(url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}})
	subnet := send(url.Values{"Action": {"CreateSubnet"}, "VpcId": {xmlText(t, vpc, "vpcId")}, "CidrBlock": {"10.0.1.0/24"}})
	run := send(url.Values{
		"Action": {"RunInstances"}, "ImageId": {"ami-0123456789abcdef0"}, "InstanceType": {"vws.small"},
		"SubnetId": {xmlText(t, subnet, "subnetId")}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {"run-tags"},
		"TagSpecification.1.ResourceType": {"instance"},
		"TagSpecification.1.Tag.1.Key":    {"Name"}, "TagSpecification.1.Tag.1.Value": {"web"},
		"TagSpecification.1.Tag.2.Key": {"env"}, "TagSpecification.1.Tag.2.Value": {"dev"},
	})
	got := send(url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {xmlText(t, run, "instanceId")}})
	for _, want := range []string{
		"<ownerId>" + cred.Account.String() + "</ownerId>",
		"<tagSet><item><key>Name</key><value>web</value></item><item><key>env</key><value>dev</value></item></tagSet>",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
}
