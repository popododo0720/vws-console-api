package ec2query

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// TestTagSpecificationReadsUpToMaxTags checks TagSpecification.1.Tag.N up to
// resource.MaxTags (50), the bound CreateTags reads. A create with tags 21
// to 50 in one specification must apply every one, not drop them (#703).
func TestTagSpecificationReadsUpToMaxTags(t *testing.T) {
	h, cred, now := harness(t)
	form := url.Values{
		"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}, "ClientToken": {"vpc-maxtags"},
		"TagSpecification.1.ResourceType": {"vpc"}, "Version": {Version},
	}
	for i := 1; i <= 50; i++ {
		n := strconv.Itoa(i)
		form.Set("TagSpecification.1.Tag."+n+".Key", "k"+n)
		form.Set("TagSpecification.1.Tag."+n+".Value", "v"+n)
	}
	res := signed(t, h, cred, now, form.Encode())
	body := res.Body.String()
	if res.Code != http.StatusOK {
		t.Fatalf("CreateVpc with 50 tags: %d %s", res.Code, body)
	}
	if !strings.Contains(body, "<key>k50</key><value>v50</value>") {
		t.Fatalf("tag 50 missing from %s", body)
	}
}

// TestTagSpecificationPast50IsUnapplied checks a 51st tag in one
// specification is never silently dropped: it is refused as an unapplied
// parameter (#703).
func TestTagSpecificationPast50IsUnapplied(t *testing.T) {
	h, cred, now := harness(t)
	form := url.Values{
		"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}, "ClientToken": {"vpc-overtags"},
		"TagSpecification.1.ResourceType": {"vpc"}, "Version": {Version},
		"TagSpecification.1.Tag.51.Key": {"over"}, "TagSpecification.1.Tag.51.Value": {"budget"},
	}
	res := signed(t, h, cred, now, form.Encode())
	if res.Code != http.StatusBadRequest {
		t.Fatalf("CreateVpc with a 51st tag: got %d, want 400 (unapplied parameter)", res.Code)
	}
}

// TestTagSpecificationRequiresResourceType checks a specification with tags
// but no ResourceType, or an empty one, is refused rather than accepted
// (#703).
func TestTagSpecificationRequiresResourceType(t *testing.T) {
	h, cred, now := harness(t)
	send := func(f url.Values) string {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		if res.Code != http.StatusOK {
			t.Fatalf("%s %d %s", f.Get("Action"), res.Code, res.Body)
		}
		return res.Body.String()
	}
	vpc := send(url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}})
	subnet := send(url.Values{
		"Action": {"CreateSubnet"}, "VpcId": {xmlText(t, vpc, "vpcId")}, "CidrBlock": {"10.0.1.0/24"},
	})
	subnetID := xmlText(t, subnet, "subnetId")
	cases := map[string]url.Values{
		"missing ResourceType": {
			"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}, "ClientToken": {"vpc-notype"},
			"TagSpecification.1.Tag.1.Key": {"Name"}, "TagSpecification.1.Tag.1.Value": {"web"},
		},
		"empty ResourceType": {
			"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}, "ClientToken": {"vpc-emptytype"},
			"TagSpecification.1.ResourceType": {""},
			"TagSpecification.1.Tag.1.Key":    {"Name"}, "TagSpecification.1.Tag.1.Value": {"web"},
		},
		"RunInstances missing ResourceType": {
			"Action": {"RunInstances"}, "ImageId": {"ami-0123456789abcdef0"}, "InstanceType": {"vws.small"},
			"SubnetId": {subnetID}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {"run-notype"},
			"TagSpecification.1.Tag.1.Key": {"Name"}, "TagSpecification.1.Tag.1.Value": {"web"},
		},
	}
	for name, form := range cases {
		t.Run(name, func(t *testing.T) {
			form.Set("Version", Version)
			res := signed(t, h, cred, now, form.Encode())
			if res.Code != http.StatusBadRequest {
				t.Fatalf("%s: got %d, want 400", name, res.Code)
			}
			if !strings.Contains(res.Body.String(), "<Code>MissingParameter</Code>") {
				t.Fatalf("%s: want MissingParameter, got %s", name, res.Body.String())
			}
		})
	}
}

// TestTagSpecificationWithOnlyResourceTypeIsAccepted checks a specification
// naming a ResourceType with no tags is not refused: EC2 allows reserving a
// slot without setting any tag.
func TestTagSpecificationWithOnlyResourceTypeIsAccepted(t *testing.T) {
	h, cred, now := harness(t)
	f := url.Values{
		"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}, "ClientToken": {"vpc-typeonly"},
		"TagSpecification.1.ResourceType": {"vpc"}, "Version": {Version},
	}
	res := signed(t, h, cred, now, f.Encode())
	if res.Code != http.StatusOK {
		t.Fatalf("CreateVpc with only ResourceType: %d %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "<vpcId>") {
		t.Fatalf("missing vpcId in %s", res.Body.String())
	}
}
