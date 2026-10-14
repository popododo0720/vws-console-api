package grpcclient

import (
	"maps"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

var labelKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

// awsTags are valid EC2 tags that compute labels cannot hold as they are.
func awsTags() map[string]string {
	return map[string]string{
		"Name":                    "web-1",
		"env":                     "dev",
		"Owner Team":              "Platform / SRE: a=b, c+d @x",
		"vws-looks-internal":      "user value",
		"aws:cloudformation:name": "stack",
		"lower_but_long_value":    strings.Repeat("v", 256),
		strings.Repeat("K", 128):  "max key",
		"유니코드":                    strings.Repeat("값", 85), // 255 bytes
		"empty":                   "",
	}
}

func checkLabels(t *testing.T, labels map[string]string) {
	t.Helper()
	if len(labels) > 64 {
		t.Fatalf("%d labels, compute takes 64", len(labels))
	}
	for k, v := range labels {
		if !labelKeyRE.MatchString(k) {
			t.Fatalf("label key %q breaks the compute grammar", k)
		}
		if len(v) > 63 || !utf8.ValidString(v) || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			t.Fatalf("label %s value %q breaks the compute grammar", k, v)
		}
	}
}

func TestTagsRoundTripThroughLabels(t *testing.T) {
	tags := awsTags()
	labels, err := withInternalLabels(tags, map[string]string{labelImage: "ami-0123456789abcdef0"})
	if err != nil {
		t.Fatal(err)
	}
	checkLabels(t, labels)
	if got := userTags(labels); !maps.Equal(got, tags) {
		t.Fatalf("round trip\n got %q\nwant %q", got, tags)
	}
	if labels["env"] != "dev" {
		t.Fatalf("a tag that is a valid label stays a plain label for filtering: %v", labels)
	}
}

func TestLegacyNameLabelStillReads(t *testing.T) {
	if got := userTags(map[string]string{labelNameTag: "old"}); got["Name"] != "old" {
		t.Fatalf("%v", got)
	}
}

func TestTagsOverLabelCapacityFail(t *testing.T) {
	tags := map[string]string{}
	for i := 0; i < 20; i++ {
		tags[strings.Repeat("K", 127)+string(rune('a'+i))] = strings.Repeat("v", 256)
	}
	if _, err := withInternalLabels(tags, nil); err == nil {
		t.Fatal("20 maximal tags cannot fit in 64 labels of 63 bytes; want an error, not silent loss")
	}
}
