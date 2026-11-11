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
	type accepted struct {
		Items []resource.SecurityGroup     `json:"items"`
		Rules []resource.SecurityGroupRule `json:"securityGroupRules"`
	}
	var acc accepted
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &acc) != nil || len(acc.Items) != 1 {
		t.Fatalf("authorize %d %s", rec.Code, rec.Body)
	}
	// #596: the added rules come back with stable sgr- ids.
	if len(acc.Rules) != 3 || acc.Rules[0].ID == acc.Rules[1].ID || acc.Rules[1].ID == acc.Rules[2].ID {
		t.Fatalf("securityGroupRules %+v", acc.Rules)
	}
	for _, r := range acc.Rules {
		if !resource.IsRuleID(r.ID) || r.GroupID.String() != sg || r.IsEgress {
			t.Fatalf("rule %+v", r)
		}
	}
	want := []resource.IngressRule{
		{Protocol: "tcp", FromPort: 22, ToPort: 22, Cidr: "10.0.0.0/16"},
		{Protocol: "tcp", FromPort: 22, ToPort: 22, Cidr: "10.1.0.0/16"},
		{Protocol: "udp", FromPort: 53, ToPort: 53, Cidr: "0.0.0.0/0"},
	}
	if got := acc.Items[0].Rules; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("rules %+v, want %+v", got, want)
	}
	again := do(http.MethodPost, path, body, "auth-several-1")
	var replay accepted
	if again.Code != http.StatusAccepted || json.Unmarshal(again.Body.Bytes(), &replay) != nil {
		t.Fatalf("retry %d %s", again.Code, again.Body)
	}
	if len(replay.Rules) != 3 || replay.Rules[0] != acc.Rules[0] || replay.Rules[2] != acc.Rules[2] {
		t.Fatalf("retry rules %+v, want %+v", replay.Rules, acc.Rules)
	}
	single := `{"ipPermissions":{"ipProtocol":"tcp","fromPort":80,"toPort":80,"cidrIp":"10.0.0.0/16"}}`
	if old := do(http.MethodPost, path, single, "auth-old-1"); old.Code != http.StatusBadRequest {
		t.Fatalf("single object %d %s", old.Code, old.Body)
	}

	// #597: revoke-ingress takes the same list, all or none, with the same
	// refusals.
	revoke := "/api/v1/security-groups/" + sg + "/revoke-ingress"
	for field, source := range refused {
		body := `{"ipPermissions":[{` + https + source + `}]}`
		rec := do(http.MethodPost, revoke, body, "revoke-refused-"+field)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"`+field+`"`) {
			t.Fatalf("revoke %s: %d %s", field, rec.Code, rec.Body)
		}
	}
	ssh := `{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":[{"cidrIp":"10.0.0.0/16"},{"cidrIp":"10.1.0.0/16"}]}`
	missing := `{"ipPermissions":[` + ssh +
		`,{"ipProtocol":"tcp","fromPort":80,"toPort":80,"ipRanges":[{"cidrIp":"10.0.0.0/16"}]}]}`
	if rec := do(http.MethodPost, revoke, missing, "revoke-missing-1"); rec.Code != http.StatusNotFound ||
		!strings.Contains(rec.Body.String(), "rule does not exist") {
		t.Fatalf("revoke with a missing rule %d %s", rec.Code, rec.Body)
	}
	rec = do(http.MethodPost, revoke, `{"ipPermissions":[`+ssh+`]}`, "revoke-several-1")
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &acc) != nil || len(acc.Items) != 1 {
		t.Fatalf("revoke %d %s", rec.Code, rec.Body)
	}
	if got := acc.Items[0].Rules; len(got) != 1 || got[0] != want[2] {
		t.Fatalf("after revoke %+v, want only %+v: a refused revoke removed a rule or this one missed one", got, want[2])
	}
	if old := do(http.MethodPost, revoke, single, "revoke-old-1"); old.Code != http.StatusBadRequest {
		t.Fatalf("revoke single object %d %s", old.Code, old.Body)
	}
}

// #219: a console ICMP permission takes the type in fromPort and the code in
// toPort. One that omits either is a 400 naming fromPort, never echo reply.
func TestAuthorizeIngressICMPTypeAndCode(t *testing.T) {
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
	var acc struct {
		Items []resource.SecurityGroup `json:"items"`
	}
	read := func(rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &acc) != nil || len(acc.Items) != 1 {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	}
	var vpc struct {
		Items []resource.Vpc `json:"items"`
	}
	vpcRec := do("/api/v1/vpcs", `{"cidrBlock":"10.5.0.0/16"}`, "vpc-icmp")
	if json.Unmarshal(vpcRec.Body.Bytes(), &vpc) != nil || len(vpc.Items) != 1 {
		t.Fatalf("vpc %d %s", vpcRec.Code, vpcRec.Body)
	}
	read(do("/api/v1/security-groups", `{"groupName":"ping","vpcId":"`+vpc.Items[0].ID.String()+`"}`, "sg-icmp"))
	path := "/api/v1/security-groups/" + acc.Items[0].ID.String() + "/authorize-ingress"
	for name, ports := range map[string]string{
		"neither": ``, "no code": `"fromPort":8,`, "null type": `"fromPort":null,"toPort":0,`,
	} {
		rec := do(path, `{"ipPermissions":[{"ipProtocol":"icmp",`+ports+`"ipRanges":[{"cidrIp":"10.0.0.0/16"}]}]}`,
			"icmp-"+strings.ReplaceAll(name, " ", "-"))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"fromPort"`) {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	ranges := `"ipRanges":[{"cidrIp":"10.0.0.0/16"}]`
	read(do(path, `{"ipPermissions":[{"ipProtocol":"icmp","fromPort":-1,"toPort":-1,`+ranges+`},`+
		`{"ipProtocol":"icmp","fromPort":8,"toPort":0,`+ranges+`}]}`, "icmp-ok"))
	want := []resource.IngressRule{
		{Protocol: "icmp", FromPort: -1, ToPort: -1, Cidr: "10.0.0.0/16"},
		{Protocol: "icmp", FromPort: 8, ToPort: 0, Cidr: "10.0.0.0/16"},
	}
	if got := acc.Items[0].Rules; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("rules %+v", got)
	}
}
