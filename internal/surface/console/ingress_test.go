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

// #217: authorize-ingress takes the AWS ipPermissions list, adds every range
// of every permission in one call, and refuses a source VWS cannot store.
func TestAuthorizeIngressTakesIPPermissions(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()})
	h := New(rootConfig(svc, account))
	do := func(method, path, body, key string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", key)
		}
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
	vpc := created(do(http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.4.0.0/16"}`, "vpc-ingress-1"), "vpcId")
	sg := created(
		do(http.MethodPost, "/api/v1/security-groups", `{"groupName":"web","vpcId":"`+vpc+`"}`, "sg-ingress-1"),
		"groupId",
	)
	path := "/api/v1/security-groups/" + sg + "/authorize-ingress"

	https := `"ipProtocol":"tcp","fromPort":443,"toPort":443,`
	refused := map[string]string{
		"ipv6Ranges":       `"ipv6Ranges":[{"cidrIpv6":"::/0"}]`,
		"userIdGroupPairs": `"userIdGroupPairs":[{"groupId":"` + sg + `"}]`,
		"prefixListIds":    `"prefixListIds":[{"prefixListId":"pl-12345678"}]`,
		"description":      `"ipRanges":[{"cidrIp":"10.2.0.0/16","description":"https"}]`,
	}
	for field, source := range refused {
		ssh := `{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":[{"cidrIp":"10.0.0.0/16"}]}`
		body := `{"ipPermissions":[` + ssh + `,{` + https + source + `}]}`
		rec := do(http.MethodPost, path, body, "auth-refused-"+field)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"`+field+`"`) {
			t.Fatalf("%s: %d %s", field, rec.Code, rec.Body)
		}
	}

	body := `{"ipPermissions":[
		{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":[{"cidrIp":"10.0.0.0/16"},{"cidrIp":"10.1.0.0/16"}]},
		{"ipProtocol":"udp","fromPort":53,"toPort":53,"ipRanges":[{"cidrIp":"0.0.0.0/0"}]}]}`
	rec := do(http.MethodPost, path, body, "auth-several-1")
	var acc struct {
		Items []resource.SecurityGroup `json:"items"`
	}
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &acc) != nil || len(acc.Items) != 1 {
		t.Fatalf("authorize %d %s", rec.Code, rec.Body)
	}
	want := []resource.IngressRule{
		{Protocol: "tcp", FromPort: 22, ToPort: 22, Cidr: "10.0.0.0/16"},
		{Protocol: "tcp", FromPort: 22, ToPort: 22, Cidr: "10.1.0.0/16"},
		{Protocol: "udp", FromPort: 53, ToPort: 53, Cidr: "0.0.0.0/0"},
	}
	if got := acc.Items[0].Rules; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("rules %+v, want %+v", got, want)
	}
	if again := do(http.MethodPost, path, body, "auth-several-1"); again.Code != http.StatusAccepted {
		t.Fatalf("retry %d %s", again.Code, again.Body)
	}
	single := `{"ipPermissions":{"ipProtocol":"tcp","fromPort":80,"toPort":80,"cidrIp":"10.0.0.0/16"}}`
	if old := do(http.MethodPost, path, single, "auth-old-1"); old.Code != http.StatusBadRequest {
		t.Fatalf("single object %d %s", old.Code, old.Body)
	}
}
