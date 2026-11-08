package ec2query

import (
	"net/http"
	"strconv"
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

func TestEveryRouteTableIDIsChecked(t *testing.T) {
	h, cred, now := harness(t)
	for _, tc := range []struct {
		name string
		ids  []string
		code string
		id   string
	}{
		{"malformed first", []string{"rtb-nope", "rtb-01234567"}, "InvalidRouteTableID.Malformed", "rtb-nope"},
		{"malformed second", []string{"rtb-01234567", "rtb-nope"}, "InvalidRouteTableID.Malformed", "rtb-nope"},
		{
			"malformed third",
			[]string{"rtb-01234567", "rtb-89abcdef", "subnet-1"},
			"InvalidRouteTableID.Malformed", "subnet-1",
		},
		{"unknown", []string{"rtb-01234567"}, "InvalidRouteTableID.NotFound", "rtb-01234567"},
		{"unknown pair", []string{"rtb-89abcdef", "rtb-01234567"}, "InvalidRouteTableID.NotFound", "rtb-89abcdef"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{}
			for i, id := range tc.ids {
				args = append(args, "RouteTableId."+strconv.Itoa(i+1), id)
			}
			res := signed(t, h, cred, now, parityForm("DescribeRouteTables", args...).Encode())
			body := res.Body.String()
			if res.Code != http.StatusBadRequest || !strings.Contains(body, "<Code>"+tc.code+"</Code>") ||
				!strings.Contains(body, tc.id) {
				t.Fatalf("%v: %d %s", tc.ids, res.Code, body)
			}
		})
	}
}
