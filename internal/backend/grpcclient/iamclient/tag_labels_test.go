package iamclient

import (
	"maps"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestKeyPairTagLabelsRoundTrip(t *testing.T) {
	tags := map[string]string{
		"Name":         "key pair",
		"plain":        "value",
		"vws-key-sha1": "user value",
		"long":         strings.Repeat("value", 30),
		"unicode":      strings.Repeat("\u20ac", 40),
	}
	internal := map[string]string{"vws-key-sha1": "fingerprint"}
	labels, err := withInternalLabels(tags, internal)
	if err != nil {
		t.Fatal(err)
	}
	if labels["vws-key-sha1"] != "fingerprint" {
		t.Fatal("user tags overwrote the internal fingerprint")
	}
	got, err := userTags(maps.Clone(labels))
	if err != nil || !maps.Equal(got, tags) {
		t.Fatalf("tags after reload = %v, %v; want %v", got, err, tags)
	}
	retry, err := withInternalLabels(got, internal)
	if err != nil || !maps.Equal(retry, labels) {
		t.Fatalf("retry labels = %v, %v; want %v", retry, err, labels)
	}
}

func TestKeyPairTagLabelsRejectMalformedAndOversized(t *testing.T) {
	for name, labels := range map[string]map[string]string{
		"missing chunk": {"vws-tags-01": "{}"},
		"bad JSON":      {"vws-tags-00": "{"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := userTags(labels); resource.CodeOf(err) != resource.CodeInternal {
				t.Fatalf("malformed labels error = %v", err)
			}
		})
	}
	if _, err := withInternalLabels(map[string]string{"Name": strings.Repeat("x", 7000)}, nil); err == nil {
		t.Fatal("oversized packed labels accepted")
	}
	tags := make(map[string]string)
	for i := range 59 {
		tags["tag"+strings.Repeat("x", i)] = "value"
	}
	if _, err := withInternalLabels(tags, nil); err == nil {
		t.Fatal("labels exceeding the internal reserve accepted")
	}
}
