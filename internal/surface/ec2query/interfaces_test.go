package ec2query

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func directHarness(t *testing.T) func(url.Values) (int, string) {
	t.Helper()
	direct, err := resource.Parse[resource.SubnetID]("subnet-direct-prod")
	if err != nil {
		t.Fatal(err)
	}
	h, cred, now := harnessWithOptions(t, fake.Options{
		Direct: []fake.DirectNetwork{{ID: direct, Cidr: "192.168.200.0/24"}},
	})
	return func(f url.Values) (int, string) {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		return res.Code, res.Body.String()
	}
}

type describedNIC struct {
	SubnetID    string `xml:"subnetId"`
	VpcID       string `xml:"vpcId"`
	PrivateIP   string `xml:"privateIpAddress"`
	DeviceIndex int    `xml:"attachment>deviceIndex"`
}

type describedInstance struct {
	ID       string         `xml:"instanceId"`
	SubnetID string         `xml:"subnetId"`
	VpcID    string         `xml:"vpcId"`
	NICs     []describedNIC `xml:"networkInterfaceSet>item"`
}

func describeAll(t *testing.T, send func(url.Values) (int, string)) []describedInstance {
	t.Helper()
	code, body := send(url.Values{"Action": {"DescribeInstances"}})
	var got struct {
		Items []describedInstance `xml:"reservationSet>item>instancesSet>item"`
	}
	if code != http.StatusOK || xml.Unmarshal([]byte(body), &got) != nil {
		t.Fatalf("describe %d %s", code, body)
	}
	return got.Items
}

func TestRunInstancesTakesNetworkInterfaces(t *testing.T) {
	send := directHarness(t)
	ok := func(f url.Values) string {
		t.Helper()
		code, body := send(f)
		if code != http.StatusOK {
			t.Fatalf("%s %d %s", f.Get("Action"), code, body)
		}
		return body
	}
	overlay := newSubnet(t, ok)
	vpc := xmlText(t, ok(url.Values{"Action": {"DescribeSubnets"}, "SubnetId.1": {overlay}}), "vpcId")
	mixed := launchForm("", "nics-mixed", url.Values{
		"NetworkInterface.1.DeviceIndex": {"1"}, "NetworkInterface.1.SubnetId": {"subnet-direct-prod"},
		"NetworkInterface.2.DeviceIndex": {"0"}, "NetworkInterface.2.SubnetId": {overlay},
	})
	mixed.Del("SubnetId")
	first := xmlText(t, ok(mixed), "instanceId")
	if again := xmlText(t, ok(mixed), "instanceId"); again != first {
		t.Fatalf("retry launched %s, want %s", again, first)
	}
	directOnly := launchForm("", "nics-direct", url.Values{
		"NetworkInterface.1.DeviceIndex": {"0"}, "NetworkInterface.1.SubnetId": {"subnet-direct-prod"},
	})
	directOnly.Del("SubnetId")
	second := xmlText(t, ok(directOnly), "instanceId")

	byID := map[string]describedInstance{}
	for _, inst := range describeAll(t, send) {
		byID[inst.ID] = inst
	}
	m, d := byID[first], byID[second]
	if len(byID) != 2 || m.SubnetID != overlay || m.VpcID != vpc || len(m.NICs) != 2 ||
		m.NICs[0] != (describedNIC{overlay, vpc, m.NICs[0].PrivateIP, 0}) ||
		m.NICs[1] != (describedNIC{"subnet-direct-prod", "vpc-direct", m.NICs[1].PrivateIP, 1}) {
		t.Fatalf("mixed launch %+v, want device 0 on %s in %s and device 1 direct", m, overlay, vpc)
	}
	if d.SubnetID != "subnet-direct-prod" || d.VpcID != "vpc-direct" || len(d.NICs) != 1 || d.NICs[0].DeviceIndex != 0 {
		t.Fatalf("direct-only launch %+v", d)
	}
}

func TestRunInstancesRefusesBadNetworkInterfaces(t *testing.T) {
	send := directHarness(t)
	const d = "subnet-direct-prod"
	// nic is a launch with one NetworkInterface member per [N, DeviceIndex,
	// SubnetId]; an empty value is left out.
	nic := func(members ...[3]string) url.Values {
		f := launchForm("", "nics-bad", nil)
		f.Del("SubnetId")
		for _, m := range members {
			prefix := "NetworkInterface." + m[0] + "."
			if m[1] != "" {
				f.Set(prefix+"DeviceIndex", m[1])
			}
			if m[2] != "" {
				f.Set(prefix+"SubnetId", m[2])
			}
		}
		return f
	}
	withSubnet := nic([3]string{"1", "0", d})
	withSubnet.Set("SubnetId", d)
	unread := nic([3]string{"1", "0", d})
	unread.Set("NetworkInterface.1.AssociatePublicIpAddress", "true")
	for name, c := range map[string]struct {
		form url.Values
		code string
	}{
		"SubnetId and NetworkInterface": {withSubnet, "InvalidParameterCombination"},
		"member 0":                      {nic([3]string{"0", "0", d}), "InvalidParameterValue"},
		"member 999":                    {nic([3]string{"999", "0", d}), "InvalidParameterValue"},
		"member 01":                     {nic([3]string{"01", "0", d}), "InvalidParameterValue"},
		"unread member field":           {unread, "InvalidParameterValue"},
		"negative index":                {nic([3]string{"1", "-1", d}), "InvalidParameterValue"},
		"index past cap":                {nic([3]string{"1", "0", d}, [3]string{"2", "8", d}), "InvalidParameterValue"},
		"text index":                    {nic([3]string{"1", "abc", d}), "InvalidParameterValue"},
		"duplicate index":               {nic([3]string{"1", "0", d}, [3]string{"2", "0", d}), "InvalidParameterValue"},
		"no device 0":                   {nic([3]string{"1", "1", d}), "InvalidParameterValue"},
		"no device index":               {nic([3]string{"1", "", d}), "MissingParameter"},
		"no subnet":                     {nic([3]string{"1", "0", ""}), "MissingParameter"},
		"malformed subnet":              {nic([3]string{"1", "0", "subnet-direct-UPPER"}), "InvalidParameterValue"},
		"missing direct":                {nic([3]string{"1", "0", "subnet-direct-nope"}), "InvalidSubnetID.NotFound"},
		"two overlay": {nic([3]string{"1", "0", "subnet-0123456789abcdef0"},
			[3]string{"2", "1", "subnet-0123456789abcdef1"}), "InvalidParameterValue"},
	} {
		code, body := send(c.form)
		if code != http.StatusBadRequest || !strings.Contains(body, "<Code>"+c.code+"</Code>") {
			t.Errorf("%s: %d %s, want 400 %s", name, code, body, c.code)
		}
	}
	if got := describeAll(t, send); len(got) != 0 {
		t.Fatalf("refused launches left instances: %+v", got)
	}
}

func TestAssociateAddressRefusesADirectPrimaryInterface(t *testing.T) {
	send := directHarness(t)
	ok := func(f url.Values) string {
		t.Helper()
		code, body := send(f)
		if code != http.StatusOK {
			t.Fatalf("%s %d %s", f.Get("Action"), code, body)
		}
		return body
	}
	overlay := newSubnet(t, ok)
	launch := func(token string, members ...[2]string) string {
		f := launchForm("", token, nil)
		f.Del("SubnetId")
		for i, m := range members {
			prefix := "NetworkInterface." + strconv.Itoa(i+1) + "."
			f.Set(prefix+"DeviceIndex", m[0])
			f.Set(prefix+"SubnetId", m[1])
		}
		return xmlText(t, ok(f), "instanceId")
	}
	direct := launch("eip-direct", [2]string{"0", "subnet-direct-prod"}, [2]string{"1", overlay})
	mixed := launch("eip-mixed", [2]string{"0", overlay}, [2]string{"1", "subnet-direct-prod"})
	alloc := func() string {
		return xmlText(t, ok(url.Values{"Action": {"AllocateAddress"}, "Domain": {"vpc"}}), "allocationId")
	}
	refused := alloc()
	code, body := send(url.Values{"Action": {"AssociateAddress"}, "AllocationId": {refused}, "InstanceId": {direct}})
	if code != http.StatusBadRequest || !strings.Contains(body, "<Code>InvalidParameterCombination</Code>") {
		t.Fatalf("direct primary %d %s", code, body)
	}
	described := ok(url.Values{"Action": {"DescribeAddresses"}, "AllocationId.1": {refused}})
	if strings.Contains(described, "<instanceId>") {
		t.Fatalf("a refused association stuck: %s", described)
	}
	ok(url.Values{"Action": {"AssociateAddress"}, "AllocationId": {alloc()}, "InstanceId": {mixed}})
	var got struct {
		NICs []struct {
			DeviceIndex int    `xml:"attachment>deviceIndex"`
			PublicIP    string `xml:"association>publicIp"`
		} `xml:"reservationSet>item>instancesSet>item>networkInterfaceSet>item"`
	}
	body = ok(url.Values{"Action": {"DescribeInstances"}, "InstanceId.1": {mixed}})
	if xml.Unmarshal([]byte(body), &got) != nil || len(got.NICs) != 2 ||
		got.NICs[0].DeviceIndex != 0 || got.NICs[0].PublicIP == "" || got.NICs[1].PublicIP != "" {
		t.Fatalf("the address is not on device 0 alone: %s", body)
	}
}
