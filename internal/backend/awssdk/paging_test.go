package awssdk

import (
	"net/http"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestAWSSDKCursorSurvivesInstanceRemoval(t *testing.T) {
	before := setup(t, "instances.xml", http.StatusOK)
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account, Region: "us-east-1"}
	first, err := before.DescribeInstances(t.Context(), scope, resource.InstanceQuery{
		Page: resource.PageRequest{Size: 1},
	})
	if err != nil || first.NextToken != "i-0123456789abcdef0" {
		t.Fatalf("initial page: %+v, %v", first, err)
	}
	for _, tc := range []struct {
		fixture string
		wantID  string
	}{
		{"instances-next.xml", "i-1123456789abcdef0"},
		{"instances-empty.xml", ""},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			after := setup(t, tc.fixture, http.StatusOK)
			page, err := after.DescribeInstances(t.Context(), scope, resource.InstanceQuery{
				Page: resource.PageRequest{Size: 1, Token: first.NextToken},
			})
			if err != nil || page.NextToken != "" {
				t.Fatalf("resumed page: %+v, %v", page, err)
			}
			if tc.wantID == "" {
				if len(page.Items) != 0 {
					t.Fatalf("removed inventory returned rows: %+v", page)
				}
			} else if len(page.Items) != 1 || page.Items[0].ID.String() != tc.wantID {
				t.Fatalf("want remaining instance %s, got %+v", tc.wantID, page)
			}
		})
	}
}
