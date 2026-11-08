package ec2query

import (
	"net/url"
	"strings"
	"testing"
)

// The EC2 filtering guide: a value of \*amazon\?\\ searches for the literal
// string *amazon?\.
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Filtering.html
func TestFilterValueEscapesAreLiteral(t *testing.T) {
	for _, tc := range []struct {
		pattern, value string
		want           bool
	}{
		{`\*amazon\?\\`, `*amazon?\`, true},
		{`\*amazon\?\\`, `xamazonx\`, false},
		{`\*`, `*`, true},
		{`\*`, `a`, false},
		{`\*`, ``, false},
		{`a\*b`, `a*b`, true},
		{`a\*b`, `axxb`, false},
		{`\?`, `?`, true},
		{`\?`, `a`, false},
		{`\\`, `\`, true},
		{`\\`, `\\`, false},
		{`\\*`, `\anything`, true},
		{`\\*`, `anything`, false},
		{`\\?`, `\a`, true},
		{`prod\*`, `prod*`, true},
		{`prod\*`, `production`, false},
		{`*\**`, `a*b`, true},
		{`*\**`, `ab`, false},
		{`a\b`, `a\b`, true},
		{`a\`, `a\`, true},
		{`a*`, `abc`, true},
		{`a?c`, `abc`, true},
		{`a?c`, `ac`, false},
		{`abc`, `abc`, true},
		{`abc`, `abd`, false},
	} {
		if got := wildcardMatch(tc.pattern, tc.value); got != tc.want {
			t.Errorf("wildcardMatch(%q, %q) = %v, want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
}

func TestDescribeVpcsTagFilterTakesEscapes(t *testing.T) {
	h, cred, now := harness(t)
	star, _ := createVpcAndSubnet(t, h, cred, now, "10.17.0.0/16", "10.17.1.0/24", url.Values{
		"TagSpecification.1.ResourceType": {"vpc"},
		"TagSpecification.1.Tag.1.Key":    {"Name"},
		"TagSpecification.1.Tag.1.Value":  {`web*?\`},
	})
	plain, _ := createVpcAndSubnet(t, h, cred, now, "10.18.0.0/16", "10.18.1.0/24", url.Values{
		"TagSpecification.1.ResourceType": {"vpc"},
		"TagSpecification.1.Tag.1.Key":    {"Name"},
		"TagSpecification.1.Tag.1.Value":  {"webxy\\"},
	})
	body := callEC2(t, h, cred, now, url.Values{
		"Action": {"DescribeVpcs"}, "Filter.1.Name": {"tag:Name"}, "Filter.1.Value.1": {`web\*\?\\`},
	})
	if !strings.Contains(body, star) || strings.Contains(body, plain) {
		t.Fatalf("escaped filter: %s", body)
	}
	body = callEC2(t, h, cred, now, url.Values{
		"Action": {"DescribeVpcs"}, "Filter.1.Name": {"tag:Name"}, "Filter.1.Value.1": {`web??\\`},
	})
	if !strings.Contains(body, star) || !strings.Contains(body, plain) {
		t.Fatalf("wildcard filter: %s", body)
	}
}
