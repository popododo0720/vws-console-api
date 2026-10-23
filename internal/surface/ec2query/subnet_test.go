package ec2query

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"testing"
)

func TestDescribeSubnetsReturnsAvailabilityZone(t *testing.T) {
	const zone = "vws-1a"
	h, cred, now := harness(t)
	call := func(action string, fields map[string]string) string {
		t.Helper()
		form := url.Values{"Action": {action}, "Version": {Version}}
		for key, value := range fields {
			form.Set(key, value)
		}
		res := signed(t, h, cred, now, form.Encode())
		if res.Code != http.StatusOK {
			t.Fatalf("%s %d %s", action, res.Code, res.Body)
		}
		return res.Body.String()
	}
	vpc := xmlText(t, call("CreateVpc", map[string]string{"CidrBlock": "10.9.0.0/16"}), "vpcId")
	created := call("CreateSubnet", map[string]string{
		"VpcId": vpc, "CidrBlock": "10.9.1.0/24", "AvailabilityZone": zone,
	})
	id := subnetIDOf(t, created)
	body := call("DescribeSubnets", map[string]string{"SubnetId.1": id})
	var got struct {
		Subnets struct {
			Items []struct {
				ID    string `xml:"subnetId"`
				Zone  string `xml:"availabilityZone"`
				MapIP bool   `xml:"mapPublicIpOnLaunch"`
			} `xml:"item"`
		} `xml:"subnetSet"`
	}
	if err := xml.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode: %v %s", err, body)
	}
	if len(got.Subnets.Items) != 1 {
		t.Fatalf("subnets %d %s", len(got.Subnets.Items), body)
	}
	subnet := got.Subnets.Items[0]
	if subnet.ID != id || subnet.Zone != zone || subnet.MapIP {
		t.Fatalf("subnet %+v, want id %s zone %s mapPublicIpOnLaunch false", subnet, id, zone)
	}
}
