package resource

import (
	"strings"
	"testing"
)

// EC2 tag keys are 1-128 Unicode characters and values 0-256. Spaces are allowed.
func TestValidTagsFollowEC2(t *testing.T) {
	for name, tags := range map[string]map[string]string{
		"space in key and value": {"Owner Team": "Platform SRE"},
		"punctuation":            {"a+b-c=d.e_f:g/h@i": "x y+z"},
		"256-character value":    {"k": strings.Repeat("값", 256)},
		"128-character key":      {strings.Repeat("키", 128): "v"},
		"empty value":            {"k": ""},
	} {
		if err := validTags(tags); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, tags := range map[string]map[string]string{
		"257-character value": {"k": strings.Repeat("v", 257)},
		"129-character key":   {strings.Repeat("k", 129): "v"},
		"empty key":           {"": "v"},
		"control character":   {"k": "a\nb"},
		"invalid UTF-8":       {"k": "\xff"},
	} {
		if err := validTags(tags); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestRequestTagsRefuseAWSKeys checks that a request may not set an aws: key,
// in any case, but a resource that already has one can take other tags.
func TestRequestTagsRefuseAWSKeys(t *testing.T) {
	id, err := Parse[InstanceID]("i-01234567")
	if err != nil {
		t.Fatal(err)
	}
	for name, tags := range map[string]map[string]string{
		"aws: prefix": {"aws:cloudformation:stack-name": "v"},
		"AWS: prefix": {"AWS:x": "v"},
	} {
		if err := validRequestTags(tags); CodeOf(err) != CodeInvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
		if _, err := (CreateTagsRequest{IDs: []InstanceID{id}, Tags: tags}).Normalize(); err == nil {
			t.Errorf("%s: CreateTags accepted it", name)
		}
	}
	got, err := MergeTags(map[string]string{"aws:cloudformation:id": "s"}, map[string]string{"Name": "web"})
	if err != nil || got["aws:cloudformation:id"] != "s" || got["Name"] != "web" {
		t.Fatalf("CreateTags on a resource with an aws: tag: %v %v", got, err)
	}
}
