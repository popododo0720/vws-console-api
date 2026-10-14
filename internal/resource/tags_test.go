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
