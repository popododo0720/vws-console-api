package ec2query

import (
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestSnapshotTags(t *testing.T) {
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
			t.Fatalf("%s: %d %s", f.Get("Action"), code, body)
		}
		return body
	}
	vol := xmlText(t, send(url.Values{
		"Action": {"CreateVolume"}, "Size": {"8"}, "AvailabilityZone": {"vws-1a"},
	}), "volumeId")
	form := url.Values{
		"Action": {"CreateSnapshot"}, "VolumeId": {vol}, "ClientToken": {"snapshot-tags"},
		"TagSpecification.1.ResourceType": {"snapshot"},
		"TagSpecification.1.Tag.1.Key":    {"Name"}, "TagSpecification.1.Tag.1.Value": {"backup"},
		"TagSpecification.2.ResourceType": {"snapshot"},
		"TagSpecification.2.Tag.1.Key":    {"env"}, "TagSpecification.2.Tag.1.Value": {"dev"},
	}
	created := send(form)
	id := xmlText(t, created, "snapshotId")
	want := "<tagSet><item><key>Name</key><value>backup</value></item>" +
		"<item><key>env</key><value>dev</value></item></tagSet>"
	if !strings.Contains(created, want) {
		t.Fatalf("CreateSnapshot missing tags: %s", created)
	}
	if replay := send(form); xmlText(t, replay, "snapshotId") != id || !strings.Contains(replay, want) {
		t.Fatalf("retry changed snapshot: %s", replay)
	}
	other := xmlText(t, send(url.Values{"Action": {"CreateSnapshot"}, "VolumeId": {vol}}), "snapshotId")
	got := send(url.Values{"Action": {"DescribeSnapshots"}, "SnapshotId.1": {id}})
	if !strings.Contains(got, want) {
		t.Fatalf("DescribeSnapshots missing tags: %s", got)
	}
	for _, tc := range []struct {
		name, value string
		match       bool
	}{
		{"tag:env", "d*", true},
		{"tag-key", "N*", true},
		{"tag:absent", "*", false},
		{"tag-key", "absent", false},
	} {
		got := send(url.Values{
			"Action": {"DescribeSnapshots"}, "Filter.1.Name": {tc.name}, "Filter.1.Value.1": {tc.value},
			"MaxResults": {"5"},
		})
		if strings.Contains(got, id) != tc.match || strings.Contains(got, other) {
			t.Fatalf("%s=%s: %s", tc.name, tc.value, got)
		}
	}
	if got := send(url.Values{"Action": {"DescribeSnapshots"}, "SnapshotId.1": {other}}); strings.Contains(got, "tagSet") {
		t.Fatalf("untagged snapshot has tags: %s", got)
	}
	for _, tc := range []struct {
		name, field, value, code, message string
	}{
		{"wrong type", "TagSpecification.1.ResourceType", "volume", "InvalidParameterValue", "must be snapshot"},
		{"reserved key", "TagSpecification.1.Tag.1.Key", "AWS:owner", "InvalidParameterValue", ""},
		{"no volume", "VolumeId", "", "MissingParameter", "VolumeId"},
		{"no resource type", "TagSpecification.1.ResourceType", "", "MissingParameter", "requires a resource type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := maps.Clone(form)
			bad.Set(tc.field, tc.value)
			code, body := call(bad)
			if code != http.StatusBadRequest || !strings.Contains(body, "<Code>"+tc.code+"</Code>") ||
				!strings.Contains(body, tc.message) {
				t.Fatalf("%d %s", code, body)
			}
		})
	}
}

func TestSnapshotMissingVolumeWithTags(t *testing.T) {
	h, cred, now := harness(t)
	f := url.Values{
		"Action": {"CreateSnapshot"}, "Version": {Version},
		"TagSpecification.1.ResourceType": {"snapshot"},
		"TagSpecification.1.Tag.1.Key":    {"owner"}, "TagSpecification.1.Tag.1.Value": {"run"},
	}
	res := signed(t, h, cred, now, f.Encode())
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "<Code>MissingParameter</Code>") ||
		!strings.Contains(res.Body.String(), "VolumeId") {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
}
