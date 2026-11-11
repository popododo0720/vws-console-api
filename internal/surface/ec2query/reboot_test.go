package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestRebootInstances checks the response shape and the unknown-id error of
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RebootInstances.html
// and https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
// (InvalidInstanceID.NotFound).
func TestRebootInstances(t *testing.T) {
	h, cred, now := harness(t)
	call := func(f url.Values) (int, string) {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		return res.Code, res.Body.String()
	}
	send := func(f url.Values) string {
		t.Helper()
		code, body := call(f)
		if code != http.StatusOK {
			t.Fatalf("%s %d %s", f.Get("Action"), code, body)
		}
		return body
	}
	vpc := send(url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}})
	subnet := send(url.Values{
		"Action": {"CreateSubnet"}, "VpcId": {xmlText(t, vpc, "vpcId")}, "CidrBlock": {"10.0.1.0/24"},
	})
	run := send(url.Values{
		"Action": {"RunInstances"}, "ImageId": {"ami-0123456789abcdef0"}, "InstanceType": {"vws.small"},
		"SubnetId": {xmlText(t, subnet, "subnetId")}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {"run-1"},
	})
	id := xmlText(t, run, "instanceId")

	body := send(url.Values{"Action": {"RebootInstances"}, "InstanceId.1": {id}})
	if !strings.Contains(body, "<RebootInstancesResponse><requestId>") || xmlText(t, body, "return") != "true" {
		t.Fatalf("reboot response %s", body)
	}

	code, body := call(url.Values{"Action": {"RebootInstances"}, "InstanceId.1": {id}, "InstanceId.2": {"i-01234567"}})
	if code != http.StatusBadRequest || !strings.Contains(body, "<Code>InvalidInstanceID.NotFound</Code>") {
		t.Fatalf("unknown instance %d %s", code, body)
	}
	if code, body := call(url.Values{"Action": {"RebootInstances"}}); code != http.StatusBadRequest {
		t.Fatalf("no instance id %d %s", code, body)
	}
	if code, body := call(url.Values{
		"Action": {"RebootInstances"}, "InstanceId.1": {id}, "ClientToken": {"reboot-1"},
	}); code != http.StatusBadRequest {
		t.Fatalf("ClientToken, which RebootInstances does not take: %d %s", code, body)
	}
}
