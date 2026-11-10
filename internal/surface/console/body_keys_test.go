package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestRepeatedOrCaseVariantKeyIsRefused pins #599: a console body whose
// object repeats a key, or whose key matches a known field only by case, is
// a 400 naming that key, on every console route and at any nesting depth.
// Found by the interrogate review of #217: the bodies below used to answer
// 202 and silently drop the field the second spelling cleared, or fill a
// field from a wrongly-cased key.
func TestRepeatedOrCaseVariantKeyIsRefused(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()})
	h := New(rootConfig(svc, account))
	do := func(path, body, key string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	created := func(rec *httptest.ResponseRecorder, field string) string {
		t.Helper()
		var acc struct {
			Items []map[string]any `json:"items"`
		}
		if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &acc) != nil || len(acc.Items) != 1 {
			t.Fatalf("create %d %s", rec.Code, rec.Body)
		}
		return acc.Items[0][field].(string)
	}
	vpc := created(do("/api/v1/vpcs", `{"cidrBlock":"10.6.0.0/16"}`, "vpc-ambiguous-1"), "vpcId")
	sg := created(
		do("/api/v1/security-groups", `{"groupName":"amb","vpcId":"`+vpc+`"}`, "sg-ambiguous-1"),
		"groupId",
	)
	path := "/api/v1/security-groups/" + sg + "/authorize-ingress"

	type testCase struct{ body, field, key string }
	cases := []testCase{
		{
			`{"ipPermissions":[{"ipProtocol":"tcp","fromPort":443,"toPort":443,` +
				`"ipRanges":[{"cidrIp":"10.0.0.0/16"}],` +
				`"ipv6Ranges":[{"cidrIpv6":"::/0"}],"ipv6Ranges":[]}]}`,
			"ipv6Ranges", "amb-dup-exact",
		},
		{
			`{"ipPermissions":[{"ipProtocol":"tcp","fromPort":443,"toPort":443,` +
				`"ipRanges":[{"cidrIp":"10.0.0.0/16"}],` +
				`"Ipv6Ranges":[{"cidrIpv6":"::/0"}],"ipv6Ranges":null}]}`,
			"Ipv6Ranges", "amb-dup-case",
		},
		{
			`{"ipPermissions":[{"ipProtocol":"tcp","fromPort":443,"toPort":443,` +
				`"ipRanges":[{"cidrIp":"10.0.0.0/16","description":"ssh","description":""}]}]}`,
			"description", "amb-nested-dup",
		},
		{
			`{"ipPermissions":[{"IpProtocol":"tcp","fromPort":443,"toPort":443,` +
				`"ipRanges":[{"cidrIp":"10.0.0.0/16"}]}]}`,
			"IpProtocol", "amb-case-field",
		},
	}
	for _, c := range cases {
		rec := do(path, c.body, c.key)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"`+c.field+`"`) {
			t.Fatalf("%s: status %d body %s", c.key, rec.Code, rec.Body)
		}
	}

	// A valid body with no repeated or case-variant key still decodes.
	ok := do(path, `{"ipPermissions":[{"ipProtocol":"tcp","fromPort":443,"toPort":443,`+
		`"ipRanges":[{"cidrIp":"10.0.0.0/16"}]}]}`, "amb-valid")
	if ok.Code != http.StatusAccepted {
		t.Fatalf("valid body: status %d body %s", ok.Code, ok.Body)
	}

	// Tag keys are case-sensitive caller data: names differing only by case
	// decode, while an exact repeat is still refused.
	tags := "/api/v1/vpcs/" + vpc + "/tags"
	if rec := do(tags, `{"tags":{"Name":"web","name":"x"}}`, "amb-tags-case"); rec.Code != http.StatusAccepted {
		t.Fatalf("tag keys differing by case: status %d body %s", rec.Code, rec.Body)
	}
	if rec := do(tags, `{"tags":{"Name":"web","Name":"x"}}`, "amb-tags-dup"); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), `"field":"Name"`) {
		t.Fatalf("repeated tag key: status %d body %s", rec.Code, rec.Body)
	}
}
