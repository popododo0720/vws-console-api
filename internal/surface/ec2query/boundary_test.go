package ec2query

import (
	"strings"
	"testing"
)

// TestMalformedQueryIsRejected sends parameters a reader could take two
// ways or that break the form encoding. Each is a 400 and changes nothing.
func TestMalformedQueryIsRejected(t *testing.T) {
	h, cred, now := harness(t)
	for name, body := range map[string]string{
		"repeated Action":    "Action=CreateVpc&Action=DeleteVpc&Version=" + Version + "&CidrBlock=10.1.0.0/16",
		"repeated CidrBlock": "Action=CreateVpc&Version=" + Version + "&CidrBlock=10.1.0.0/16&CidrBlock=10.2.0.0/16",
		"bad escape":         "Action=CreateVpc&Version=" + Version + "&CidrBlock=%zz",
		"zero index":         "Action=StopInstances&Version=" + Version + "&InstanceId.0=i-01234567",
		"oversized id":       "Action=StopInstances&Version=" + Version + "&InstanceId.1=i-" + strings.Repeat("0", 4096),
	} {
		t.Run(name, func(t *testing.T) {
			res := signed(t, h, cred, now, body)
			if res.Code != 400 {
				t.Fatalf("%d %s", res.Code, res.Body)
			}
		})
	}
	for _, body := range []string{"Version=" + Version, "Action=DropTables&Version=" + Version} {
		res := signed(t, h, cred, now, body)
		if res.Code != 400 || !strings.Contains(res.Body.String(), "<Code>InvalidAction</Code>") {
			t.Fatalf("%s: %d %s", body, res.Code, res.Body)
		}
	}
	vpcs := signed(t, h, cred, now, "Action=DescribeVpcs&Version="+Version)
	if strings.Contains(vpcs.Body.String(), "10.1.0.0/16") || strings.Contains(vpcs.Body.String(), "10.2.0.0/16") {
		t.Fatalf("a rejected request created a vpc: %s", vpcs.Body)
	}
}
