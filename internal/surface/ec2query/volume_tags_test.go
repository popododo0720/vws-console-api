package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Volume tags follow EC2: TagSpecification with ResourceType volume on
// CreateVolume, CreateTags on a vol- id, tagSet in CreateVolume and
// DescribeVolumes, tag:<key> filters, and DescribeTags rows of type volume.
func TestVolumeTags(t *testing.T) {
	h, cred, now := harness(t)
	call := func(f url.Values) (int, string) {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		return res.Code, res.Body.String()
	}
	send := func(f url.Values) string {
		t.Helper()
		code, body := call(f)
		if code != http.StatusOK {
			t.Fatalf("%s %d %s", f.Get("Action"), code, body)
		}
		return body
	}
	created := send(url.Values{
		"Action": {"CreateVolume"}, "Size": {"8"}, "AvailabilityZone": {"vws-1a"},
		"TagSpecification.1.ResourceType": {"volume"},
		"TagSpecification.1.Tag.1.Key":    {"Name"}, "TagSpecification.1.Tag.1.Value": {"data"},
	})
	if want := "<tagSet><item><key>Name</key><value>data</value></item></tagSet>"; !strings.Contains(created, want) {
		t.Fatalf("CreateVolume missing %s in %s", want, created)
	}
	volID := xmlText(t, created, "volumeId")
	plain := url.Values{"Action": {"CreateVolume"}, "Size": {"8"}, "AvailabilityZone": {"vws-1a"}}
	other := xmlText(t, send(plain), "volumeId")

	send(url.Values{
		"Action": {"CreateTags"}, "ResourceId.1": {volID},
		"Tag.1.Key": {"env"}, "Tag.1.Value": {"dev"}, "Tag.2.Key": {"Name"}, "Tag.2.Value": {"data-2"},
	})
	got := send(url.Values{"Action": {"DescribeVolumes"}, "VolumeId.1": {volID}})
	want := "<tagSet><item><key>Name</key><value>data-2</value></item>" +
		"<item><key>env</key><value>dev</value></item></tagSet>"
	if !strings.Contains(got, want) {
		t.Fatalf("DescribeVolumes missing %s in %s", want, got)
	}

	filtered := send(url.Values{"Action": {"DescribeVolumes"}, "Filter.1.Name": {"tag:env"}, "Filter.1.Value.1": {"dev"}})
	if !strings.Contains(filtered, volID) || strings.Contains(filtered, other) {
		t.Fatalf("tag:env filter: %s", filtered)
	}

	byKey := send(url.Values{"Action": {"DescribeVolumes"}, "Filter.1.Name": {"tag-key"}, "Filter.1.Value.1": {"e*"}})
	if !strings.Contains(byKey, volID) || strings.Contains(byKey, other) {
		t.Fatalf("tag-key filter: %s", byKey)
	}
	vpc := xmlText(t, send(url.Values{
		"Action": {"CreateVpc"}, "CidrBlock": {"10.9.0.0/16"},
		"TagSpecification.1.ResourceType": {"vpc"},
		"TagSpecification.1.Tag.1.Key":    {"team"}, "TagSpecification.1.Tag.1.Value": {"a"},
	}), "vpcId")
	plainVpc := xmlText(t, send(url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.8.0.0/16"}}), "vpcId")
	vpcs := send(url.Values{"Action": {"DescribeVpcs"}, "Filter.1.Name": {"tag-key"}, "Filter.1.Value.1": {"team"}})
	if !strings.Contains(vpcs, vpc) || strings.Contains(vpcs, plainVpc) {
		t.Fatalf("DescribeVpcs tag-key filter: %s", vpcs)
	}

	tags := send(url.Values{
		"Action": {"DescribeTags"}, "Filter.1.Name": {"resource-type"}, "Filter.1.Value.1": {"volume"},
	})
	for _, want := range []string{
		"<resourceId>" + volID + "</resourceId>", "<resourceType>volume</resourceType>", "<key>env</key>",
	} {
		if !strings.Contains(tags, want) {
			t.Fatalf("DescribeTags missing %s in %s", want, tags)
		}
	}

	for name, f := range map[string]url.Values{
		"wrong resource type": {
			"Action": {"CreateVolume"}, "Size": {"8"}, "AvailabilityZone": {"vws-1a"},
			"TagSpecification.1.ResourceType": {"instance"},
			"TagSpecification.1.Tag.1.Key":    {"Name"}, "TagSpecification.1.Tag.1.Value": {"x"},
		},
		"aws: prefix": {
			"Action": {"CreateVolume"}, "Size": {"8"}, "AvailabilityZone": {"vws-1a"},
			"TagSpecification.1.ResourceType": {"volume"},
			"TagSpecification.1.Tag.1.Key":    {"aws:x"}, "TagSpecification.1.Tag.1.Value": {"x"},
		},
	} {
		code, body := call(f)
		if code != http.StatusBadRequest || !strings.Contains(body, "InvalidParameterValue") {
			t.Fatalf("%s: %d %s", name, code, body)
		}
	}
	code, body := call(url.Values{
		"Action": {"CreateTags"}, "ResourceId.1": {"vol-0fffffffffffffff0"}, "Tag.1.Key": {"k"}, "Tag.1.Value": {"v"},
	})
	if code != http.StatusBadRequest || !strings.Contains(body, "InvalidVolume.NotFound") {
		t.Fatalf("CreateTags on a missing volume: %d %s", code, body)
	}
	if got := send(url.Values{"Action": {"DescribeVolumes"}, "VolumeId.1": {other}}); strings.Contains(got, "tagSet") {
		t.Fatalf("untagged volume has a tagSet: %s", got)
	}
}

// TestDeleteTagsRefusesVolumesForNow checks that DeleteTags refuses a vol-
// id, alone or beside a VPC, before writing anything, until DeleteTags on
// volumes lands.
func TestDeleteTagsRefusesVolumesForNow(t *testing.T) {
	h, cred, now := harness(t)
	send := func(f url.Values) (int, string) {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		return res.Code, res.Body.String()
	}
	_, body := send(url.Values{
		"Action": {"CreateVolume"}, "Size": {"1"}, "AvailabilityZone": {"vws-1a"},
		"TagSpecification.1.ResourceType": {"volume"},
		"TagSpecification.1.Tag.1.Key":    {"Name"}, "TagSpecification.1.Tag.1.Value": {"data"},
	})
	vol := xmlText(t, body, "volumeId")
	_, body = send(url.Values{"Action": {"CreateVpc"}, "CidrBlock": {"10.0.0.0/16"}})
	vpc := xmlText(t, body, "vpcId")
	send(url.Values{"Action": {"CreateTags"}, "ResourceId.1": {vpc}, "Tag.1.Key": {"env"}, "Tag.1.Value": {"dev"}})
	for _, f := range []url.Values{
		{"Action": {"DeleteTags"}, "ResourceId.1": {vol}, "Tag.1.Key": {"Name"}},
		{"Action": {"DeleteTags"}, "ResourceId.1": {vpc}, "ResourceId.2": {vol}, "Tag.1.Key": {"env"}},
	} {
		if code, got := send(f); code != http.StatusBadRequest || !strings.Contains(got, "InvalidParameterValue") {
			t.Fatalf("DeleteTags %v: %d %s", f, code, got)
		}
	}
	_, got := send(url.Values{"Action": {"DescribeVolumes"}, "VolumeId.1": {vol}})
	if !strings.Contains(got, "<key>Name</key>") {
		t.Fatalf("a refused DeleteTags changed the volume tags: %s", got)
	}
	_, got = send(url.Values{"Action": {"DescribeVpcs"}, "VpcId.1": {vpc}})
	if !strings.Contains(got, "<key>env</key>") {
		t.Fatalf("a refused DeleteTags changed the vpc tags: %s", got)
	}
}
