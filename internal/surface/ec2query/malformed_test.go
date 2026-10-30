package ec2query

import (
	"net/http"
	"net/url"
	"testing"
)

// #246: AWS answers a malformed instance ID as InvalidInstanceID.Malformed,
// not InvalidParameterValue, on every instance action.
func TestMalformedInstanceIDIsInvalidInstanceIDMalformed(t *testing.T) {
	const wantMessage = "The instance ID 'i-xyz' is malformed."
	for _, tc := range []struct {
		action string
		param  string
		extra  url.Values
	}{
		{action: "DescribeInstances", param: "InstanceId.1"},
		{action: "StopInstances", param: "InstanceId.1"},
		{
			action: "DescribeInstanceAttribute",
			param:  "InstanceId",
			extra:  url.Values{"Attribute": {"userData"}},
		},
	} {
		t.Run(tc.action, func(t *testing.T) {
			h, cred, now := harness(t)
			form := url.Values{}
			form.Set("Action", tc.action)
			form.Set("Version", Version)
			form.Set(tc.param, "i-xyz")
			for key, values := range tc.extra {
				for _, value := range values {
					form.Add(key, value)
				}
			}
			res := signed(t, h, cred, now, form.Encode())
			if res.Code != http.StatusBadRequest {
				t.Fatalf("status %d body %s", res.Code, res.Body)
			}
			got := ec2ErrorXML(t, res.Body.Bytes())
			if got.Code != "InvalidInstanceID.Malformed" || got.Message != wantMessage {
				t.Fatalf("code %q message %q", got.Code, got.Message)
			}
		})
	}
}
