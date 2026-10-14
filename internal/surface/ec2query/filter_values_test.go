package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// A filter with several values matches any of them, as in EC2.
func TestInstanceStateFilterTakesSeveralValues(t *testing.T) {
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
		"SubnetId": {xmlText(t, subnet, "subnetId")}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {"run-filter"},
	})
	id := xmlText(t, run, "instanceId")
	got := send(url.Values{
		"Action": {"DescribeInstances"}, "Filter.1.Name": {"instance-state-name"},
		"Filter.1.Value.1": {"stopped"}, "Filter.1.Value.2": {"running"},
	})
	if !strings.Contains(got, id) {
		t.Fatalf("running instance missing from stopped|running: %s", got)
	}
	none := send(url.Values{
		"Action": {"DescribeInstances"}, "Filter.1.Name": {"instance-state-name"},
		"Filter.1.Value.1": {"stopped"}, "Filter.1.Value.2": {"terminated"},
	})
	if strings.Contains(none, id) {
		t.Fatalf("running instance matched stopped|terminated: %s", none)
	}
}
