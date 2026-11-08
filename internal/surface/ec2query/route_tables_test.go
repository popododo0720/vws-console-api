package ec2query

import (
	"net/http"
	"strings"
	"testing"
)

// DescribeRouteTables documents tag:<key> and tag-key, not a bare tag.
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeRouteTables.html
func TestDescribeRouteTablesRefusesTheBareTagFilter(t *testing.T) {
	h, cred, now := harness(t)
	bare := signed(t, h, cred, now, parityForm("DescribeRouteTables",
		"Filter.1.Name", "tag", "Filter.1.Value.1", "dev").Encode())
	if bare.Code != http.StatusBadRequest || !strings.Contains(bare.Body.String(), "InvalidParameterValue") {
		t.Fatalf("bare tag %d %s", bare.Code, bare.Body)
	}
	for _, name := range []string{"tag:env", "tag-key"} {
		res := signed(t, h, cred, now, parityForm("DescribeRouteTables",
			"Filter.1.Name", name, "Filter.1.Value.1", "dev").Encode())
		if res.Code != http.StatusOK {
			t.Fatalf("%s %d %s", name, res.Code, res.Body)
		}
	}
}
