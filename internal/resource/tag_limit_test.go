package resource

import (
	"fmt"
	"testing"
)

// EC2 allows 50 user tags per resource; 51 is too many (#303).
func TestTagLimitIsTheAWSLimit(t *testing.T) {
	if MaxTags != 50 {
		t.Fatalf("MaxTags = %d, want 50", MaxTags)
	}
	tags := map[string]string{}
	for i := range MaxTags {
		tags[fmt.Sprintf("k%02d", i)] = "v"
	}
	if _, err := MergeTags(nil, tags); err != nil {
		t.Fatalf("%d tags: %v", len(tags), err)
	}
	if _, err := MergeTags(tags, map[string]string{"one-more": "v"}); CodeOf(err) != CodeInvalidArgument {
		t.Fatalf("%d tags: %v, want too many", len(tags)+1, err)
	}
}
