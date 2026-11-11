package ec2query

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

const invalidVpcRangeMessage = "The CIDR block range is not valid. " +
	"The block range must be between a /28 netmask and /16 netmask."

func TestCreateVpcRefusesPrefixOutsideSixteenToTwentyEight(t *testing.T) {
	h, cred, now := harness(t)
	send := func(form url.Values) (int, string) {
		t.Helper()
		form.Set("Version", Version)
		res := signed(t, h, cred, now, form.Encode())
		return res.Code, res.Body.String()
	}
	countVpcs := func() int {
		t.Helper()
		_, body := send(url.Values{"Action": {"DescribeVpcs"}})
		return strings.Count(body, "<vpcId>")
	}
	before := countVpcs()
	cases := []struct {
		cidr string
		ok   bool
	}{
		{"10.0.0.0/15", false},
		{"10.0.0.0/16", true},
		{"10.1.0.0/28", true},
		{"10.2.0.0/29", false},
		{"10.44.0.0/29", false},
		{"10.3.0.5/29", false},
	}
	created := 0
	for i, c := range cases {
		form := url.Values{"Action": {"CreateVpc"}, "CidrBlock": {c.cidr}, "ClientToken": {"vpc-range-" + strconv.Itoa(i)}}
		for range 2 {
			code, body := send(form)
			if c.ok {
				if code != http.StatusOK {
					t.Fatalf("%s: status %d %s, want 200", c.cidr, code, body)
				}
				continue
			}
			if code != http.StatusBadRequest || xmlText(t, body, "Code") != "InvalidVpcRange" {
				t.Fatalf("%s: status %d %s, want 400 InvalidVpcRange", c.cidr, code, body)
			}
			if got := xmlText(t, body, "Message"); got != invalidVpcRangeMessage {
				t.Fatalf("%s: message %q, want %q", c.cidr, got, invalidVpcRangeMessage)
			}
		}
		if c.ok {
			created++
		}
	}
	if got := countVpcs(); got != before+created {
		t.Fatalf("vpcs %d, want %d: a refused block must create nothing", got, before+created)
	}
}
