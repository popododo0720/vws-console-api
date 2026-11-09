package ec2query

import (
	"net/http"
	"strings"
	"testing"
)

// An InstanceType.N VWS does not offer is InvalidInstanceType naming every
// unknown type in request order (tibanna#382 quotes the EC2 sentence).
func TestUnknownInstanceTypeIsInvalidInstanceType(t *testing.T) {
	h, cred, now := harness(t)
	res := signed(t, h, cred, now, parityForm("DescribeInstanceTypes",
		"InstanceType.1", "m1.medium", "InstanceType.2", "vws.small", "InstanceType.3", "m3.medium",
		"InstanceType.4", "m1.medium").Encode())
	want := "<Code>InvalidInstanceType</Code><Message>" +
		"The following supplied instance types do not exist: [m1.medium, m3.medium]</Message>"
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), want) {
		t.Fatalf("unknown types %d %s", res.Code, res.Body)
	}
	known := signed(t, h, cred, now, parityForm("DescribeInstanceTypes",
		"InstanceType.1", "vws.small", "InstanceType.2", "vws.medium").Encode())
	body := known.Body.String()
	if known.Code != http.StatusOK || strings.Count(body, "<instanceType>") != 2 ||
		!strings.Contains(body, "<instanceType>vws.medium</instanceType>") {
		t.Fatalf("known types %d %s", known.Code, body)
	}
}

// A ZoneName.N EC2 does not know is InvalidParameterValue,
// "Invalid availability zone: [name]" (floci-io/floci#5519).
func TestUnknownZoneNameIsInvalidParameterValue(t *testing.T) {
	h, cred, now := harness(t)
	res := signed(t, h, cred, now, parityForm("DescribeAvailabilityZones",
		"ZoneName.1", "vws-1a", "ZoneName.2", "vws-9z", "ZoneName.3", "us-east-1a").Encode())
	want := "<Code>InvalidParameterValue</Code><Message>Invalid availability zone: [vws-9z, us-east-1a]</Message>"
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), want) {
		t.Fatalf("unknown zones %d %s", res.Code, res.Body)
	}
	known := signed(t, h, cred, now, parityForm("DescribeAvailabilityZones", "ZoneName.1", "vws-1a").Encode())
	if known.Code != http.StatusOK || !strings.Contains(known.Body.String(), "<zoneName>vws-1a</zoneName>") {
		t.Fatalf("known zone %d %s", known.Code, known.Body)
	}
}

// No source documents an error for an unknown RegionName.N, and the
// DescribeRegions reference says only that the names filter the list, so an
// unknown name leaves an empty list (#446).
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeRegions.html
func TestUnknownRegionNameIsAnEmptyList(t *testing.T) {
	h, cred, now := harness(t)
	res := signed(t, h, cred, now, parityForm("DescribeRegions", "RegionName.1", "us-east-1").Encode())
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "<regionInfo></regionInfo>") {
		t.Fatalf("unknown region %d %s", res.Code, res.Body)
	}
}
