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

func TestAuthorizeIngressTakesThePermissionList(t *testing.T) {
	h := newIngressHarness(t)
	group := h.group(t)

	body := `{
		"ipPermissions": [
			{
				"ipProtocol": "udp",
				"fromPort": 53,
				"toPort": 53,
				"ipRanges": [{"cidrIp": "10.1.0.0/24"}]
			},
			{
				"ipProtocol": "tcp",
				"fromPort": 80,
				"toPort": 80,
				"ipRanges": [
					{"cidrIp": "192.168.1.0/24"},
					{"cidrIp": "10.0.0.0/16"}
				]
			}
		]
	}`
	first := h.post(t, "/api/v1/security-groups/"+group+"/authorize-ingress", body, "sg-in-1")
	if first.Code != http.StatusAccepted {
		t.Fatalf("authorize %d %s", first.Code, first.Body)
	}
	rules := acceptedRules(t, first.Body.Bytes())
	want := []string{"tcp 80 80 10.0.0.0/16", "tcp 80 80 192.168.1.0/24", "udp 53 53 10.1.0.0/24"}
	if strings.Join(rules, ",") != strings.Join(want, ",") {
		t.Fatalf("rules %v", rules)
	}
	raw := first.Body.String()
	if strings.Contains(raw, "securityGroupRuleSet") || strings.Contains(raw, "description") {
		t.Fatalf("response leaked a field the group does not store: %s", raw)
	}
	op := operationID(t, first.Body.Bytes())

	again := h.post(t, "/api/v1/security-groups/"+group+"/authorize-ingress", reorderIngressBody, "sg-in-1")
	if again.Code != http.StatusAccepted || operationID(t, again.Body.Bytes()) != op {
		t.Fatalf("replay %d %s", again.Code, again.Body)
	}

	mismatch := h.post(t, "/api/v1/security-groups/"+group+"/authorize-ingress", `{
		"ipPermissions": [{
			"ipProtocol": "tcp", "fromPort": 80, "toPort": 80,
			"ipRanges": [{"cidrIp": "10.9.0.0/16"}]
		}]
	}`, "sg-in-1")
	if mismatch.Code != http.StatusConflict || errorField(t, mismatch.Body.Bytes()).Code != "IdempotencyMismatch" {
		t.Fatalf("mismatch %d %s", mismatch.Code, mismatch.Body)
	}
	if got := h.rules(t, group); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("mismatch wrote rules %v", got)
	}

	dup := h.post(t, "/api/v1/security-groups/"+group+"/authorize-ingress", `{
		"ipPermissions": [{
			"ipProtocol": "tcp", "fromPort": 80, "toPort": 80,
			"ipRanges": [{"cidrIp": "10.2.0.0/16"}, {"cidrIp": "10.0.0.0/16"}]
		}]
	}`, "sg-in-2")
	got := errorField(t, dup.Body.Bytes())
	if dup.Code != http.StatusConflict || got.Code != "AlreadyExists" || got.EC2Code != "InvalidPermission.Duplicate" {
		t.Fatalf("duplicate %d %+v %s", dup.Code, got, dup.Body)
	}
	if got.Field != "ipPermissions[0].ipRanges[1]" {
		t.Fatalf("duplicate field %q", got.Field)
	}
	if listed := h.rules(t, group); strings.Join(listed, ",") != strings.Join(want, ",") {
		t.Fatalf("duplicate wrote rules %v", listed)
	}
}

func TestAuthorizeIngressRequiresPortsForTCPAndUDP(t *testing.T) {
	h := newIngressHarness(t)
	group := h.group(t)
	path := "/api/v1/security-groups/" + group + "/authorize-ingress"
	cases := []struct {
		name  string
		body  string
		field string
	}{
		{
			name: "omit-both",
			body: `{
				"ipPermissions": [{
					"ipProtocol": "tcp",
					"ipRanges": [{"cidrIp": "10.0.0.0/16"}]
				}]
			}`,
			field: "ipPermissions[0].fromPort",
		},
		{
			name: "omit-to",
			body: `{
				"ipPermissions": [{
					"ipProtocol": "udp",
					"fromPort": 53,
					"ipRanges": [{"cidrIp": "10.0.0.0/16"}]
				}]
			}`,
			field: "ipPermissions[0].toPort",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := h.post(t, path, tc.body, "sg-port-"+tc.name)
			got := errorField(t, rec.Body.Bytes())
			if rec.Code != http.StatusBadRequest || got.EC2Code != "InvalidParameterValue" || got.Field != tc.field {
				t.Fatalf("%d %+v %s", rec.Code, got, rec.Body)
			}
			if rules := h.rules(t, group); len(rules) != 0 {
				t.Fatalf("missing port wrote %v", rules)
			}
		})
	}
	fresh := newIngressHarness(t)
	zeroGroup := fresh.group(t)
	zero := fresh.post(t, "/api/v1/security-groups/"+zeroGroup+"/authorize-ingress", `{
		"ipPermissions": [{
			"ipProtocol": "tcp",
			"fromPort": 0,
			"toPort": 0,
			"ipRanges": [{"cidrIp": "10.0.0.0/16"}]
		}]
	}`, "sg-port-zero")
	if zero.Code != http.StatusAccepted {
		t.Fatalf("explicit zero %d %s", zero.Code, zero.Body)
	}
	if got := fresh.rules(t, zeroGroup); len(got) != 1 || got[0] != "tcp 0 0 10.0.0.0/16" {
		t.Fatalf("explicit zero stored %v", got)
	}
}

func TestAuthorizeIngressRequiresICMPTypeAndCode(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		field string
	}{
		{
			name: "omit-both",
			body: `{
				"ipPermissions": [{
					"ipProtocol": "icmp",
					"ipRanges": [{"cidrIp": "10.0.0.0/16"}]
				}]
			}`,
			field: "ipPermissions[0].fromPort",
		},
		{
			name: "omit-from",
			body: `{
				"ipPermissions": [{
					"ipProtocol": "icmp",
					"toPort": 0,
					"ipRanges": [{"cidrIp": "10.0.0.0/16"}]
				}]
			}`,
			field: "ipPermissions[0].fromPort",
		},
		{
			name: "omit-to",
			body: `{
				"ipPermissions": [{
					"ipProtocol": "icmp",
					"fromPort": 0,
					"ipRanges": [{"cidrIp": "10.0.0.0/16"}]
				}]
			}`,
			field: "ipPermissions[0].toPort",
		},
		{
			name: "protocol-number",
			body: `{
				"ipPermissions": [{
					"ipProtocol": "1",
					"ipRanges": [{"cidrIp": "10.0.0.0/16"}]
				}]
			}`,
			field: "ipPermissions[0].fromPort",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newIngressHarness(t)
			group := h.group(t)
			path := "/api/v1/security-groups/" + group + "/authorize-ingress"
			rec := h.post(t, path, tc.body, "sg-icmp-"+tc.name)
			got := errorField(t, rec.Body.Bytes())
			if rec.Code != http.StatusBadRequest || got.EC2Code != "InvalidParameterValue" || got.Field != tc.field {
				t.Fatalf("%d %+v %s", rec.Code, got, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), "Must specify both from and to ports with ICMP.") {
				t.Fatalf("icmp omission %s", rec.Body)
			}
			if rules := h.rules(t, group); len(rules) != 0 {
				t.Fatalf("missing icmp wrote %v", rules)
			}
		})
	}
	fresh := newIngressHarness(t)
	zeroGroup := fresh.group(t)
	zero := fresh.post(t, "/api/v1/security-groups/"+zeroGroup+"/authorize-ingress", `{
		"ipPermissions": [{
			"ipProtocol": "icmp",
			"fromPort": 0,
			"toPort": 0,
			"ipRanges": [{"cidrIp": "10.0.0.0/16"}]
		}]
	}`, "sg-icmp-zero")
	got := errorField(t, zero.Body.Bytes())
	if zero.Code != http.StatusBadRequest || got.EC2Code != "UnsupportedOperation" ||
		got.Field != "ipPermissions[0].fromPort" {
		t.Fatalf("explicit icmp zero %d %+v %s", zero.Code, got, zero.Body)
	}
	if rules := fresh.rules(t, zeroGroup); len(rules) != 0 {
		t.Fatalf("explicit icmp zero stored %v", rules)
	}
}

func TestAuthorizeIngressRefusesUnsupportedSources(t *testing.T) {
	h := newIngressHarness(t)
	group := h.group(t)
	path := "/api/v1/security-groups/" + group + "/authorize-ingress"
	cases := []struct {
		name   string
		body   string
		status int
		code   string
		ec2    string
		field  string
	}{
		{
			name:   "old-object",
			body:   `{"ipPermissions":{"ipProtocol":"tcp","fromPort":22,"toPort":22,"cidrIp":"10.0.0.0/16"}}`,
			status: http.StatusBadRequest,
			code:   "InvalidArgument",
			ec2:    "InvalidPermission.Malformed",
			field:  "body",
		},
		{
			name:   "empty-list",
			body:   `{"ipPermissions":[]}`,
			status: http.StatusBadRequest,
			code:   "InvalidArgument",
			ec2:    "InvalidPermission.Malformed",
			field:  "ipPermissions",
		},
		{
			name: "ipv6",
			body: `{
				"ipPermissions": [{
					"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
					"ipRanges": [{"cidrIp": "10.0.0.0/16"}],
					"ipv6Ranges": [{"cidrIpv6": "2001:db8::/64"}]
				}]
			}`,
			status: http.StatusBadRequest,
			code:   "InvalidArgument",
			ec2:    "UnsupportedOperation",
			field:  "ipPermissions[0].ipv6Ranges",
		},
		{
			name: "group-pair",
			body: `{
				"ipPermissions": [{
					"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
					"userIdGroupPairs": [{"groupId": "sg-01234567"}]
				}]
			}`,
			status: http.StatusBadRequest,
			code:   "InvalidArgument",
			ec2:    "UnsupportedOperation",
			field:  "ipPermissions[0].userIdGroupPairs",
		},
		{
			name: "prefix-list",
			body: `{
				"ipPermissions": [{
					"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
					"prefixListIds": [{"prefixListId": "pl-01234567"}]
				}]
			}`,
			status: http.StatusBadRequest,
			code:   "InvalidArgument",
			ec2:    "UnsupportedOperation",
			field:  "ipPermissions[0].prefixListIds",
		},
		{
			name: "prefix-malformed",
			body: `{
				"ipPermissions": [{
					"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
					"prefixListIds": [{"prefixListId": "pl-ZZ"}]
				}]
			}`,
			status: http.StatusBadRequest,
			code:   "InvalidArgument",
			ec2:    "InvalidPrefixListId.Malformed",
			field:  "ipPermissions[0].prefixListIds",
		},
		{
			name: "description",
			body: `{
				"ipPermissions": [{
					"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
					"ipRanges": [{"cidrIp": "10.0.0.0/16", "description": "office"}]
				}]
			}`,
			status: http.StatusBadRequest,
			code:   "InvalidArgument",
			ec2:    "InvalidParameterValue",
			field:  "ipPermissions[0].ipRanges[0].description",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := h.post(t, path, tc.body, "sg-refuse-"+tc.name)
			got := errorField(t, rec.Body.Bytes())
			if rec.Code != tc.status || got.Code != tc.code || got.EC2Code != tc.ec2 || got.Field != tc.field {
				t.Fatalf("%d %+v %s", rec.Code, got, rec.Body)
			}
			if rules := h.rules(t, group); len(rules) != 0 {
				t.Fatalf("refusal wrote %v", rules)
			}
		})
	}
}

const reorderIngressBody = `{
	"ipPermissions": [
		{
			"ipProtocol": "tcp",
			"fromPort": 80,
			"toPort": 80,
			"ipRanges": [
				{"cidrIp": "10.0.0.0/16"},
				{"cidrIp": "192.168.1.0/24"}
			]
		},
		{
			"ipProtocol": "udp",
			"fromPort": 53,
			"toPort": 53,
			"ipRanges": [{"cidrIp": "10.1.0.0/24"}]
		}
	]
}`

type ingressHarness struct {
	h http.Handler
}

func newIngressHarness(t *testing.T) ingressHarness {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()})
	return ingressHarness{h: New(rootConfig(svc, account))}
}

func (h ingressHarness) post(t *testing.T, path, body, key string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", key)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func (h ingressHarness) group(t *testing.T) string {
	t.Helper()
	vpc := itemID(t, h.post(t, "/api/v1/vpcs", `{"cidrBlock":"10.4.0.0/16"}`, "sg-vpc"), "vpcId")
	return itemID(t, h.post(t, "/api/v1/security-groups", `{"groupName":"web","vpcId":"`+vpc+`"}`, "sg-create"), "groupId")
}

func (h ingressHarness) rules(t *testing.T, group string) []string {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/security-groups", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list %d %s", rec.Code, rec.Body)
	}
	var page struct {
		Items []struct {
			ID    string `json:"groupId"`
			Rules []struct {
				Protocol string `json:"ipProtocol"`
				From     int    `json:"fromPort"`
				To       int    `json:"toPort"`
				Cidr     string `json:"cidrIp"`
			} `json:"ipPermissions"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	for _, item := range page.Items {
		if item.ID != group {
			continue
		}
		out := make([]string, 0, len(item.Rules))
		for _, rule := range item.Rules {
			out = append(out, strings.Join([]string{
				rule.Protocol,
				itoa(rule.From),
				itoa(rule.To),
				rule.Cidr,
			}, " "))
		}
		return out
	}
	t.Fatalf("group %s missing from %s", group, rec.Body)
	return nil
}

func itemID(t *testing.T, rec *httptest.ResponseRecorder, field string) string {
	t.Helper()
	var acc struct {
		Items []map[string]any `json:"items"`
	}
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &acc) != nil || len(acc.Items) != 1 {
		t.Fatalf("create %d %s", rec.Code, rec.Body)
	}
	id, _ := acc.Items[0][field].(string)
	if id == "" {
		t.Fatalf("missing %s in %s", field, rec.Body)
	}
	return id
}

func acceptedRules(t *testing.T, body []byte) []string {
	t.Helper()
	var acc struct {
		Items []struct {
			Rules []struct {
				Protocol string `json:"ipProtocol"`
				From     int    `json:"fromPort"`
				To       int    `json:"toPort"`
				Cidr     string `json:"cidrIp"`
			} `json:"ipPermissions"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &acc); err != nil || len(acc.Items) != 1 {
		t.Fatalf("accepted %s", body)
	}
	out := make([]string, 0, len(acc.Items[0].Rules))
	for _, rule := range acc.Items[0].Rules {
		out = append(out, strings.Join([]string{rule.Protocol, itoa(rule.From), itoa(rule.To), rule.Cidr}, " "))
	}
	return out
}

func operationID(t *testing.T, body []byte) string {
	t.Helper()
	var acc struct {
		Operation struct {
			ID string `json:"id"`
		} `json:"operation"`
	}
	if err := json.Unmarshal(body, &acc); err != nil || acc.Operation.ID == "" {
		t.Fatalf("operation %s", body)
	}
	return acc.Operation.ID
}

type consoleErr struct {
	Code    string `json:"code"`
	Field   string `json:"field"`
	EC2Code string `json:"ec2Code"`
}

func errorField(t *testing.T, body []byte) consoleErr {
	t.Helper()
	var wrap struct {
		Error consoleErr `json:"error"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		t.Fatalf("error json %s", body)
	}
	return wrap.Error
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
