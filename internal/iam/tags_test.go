package iam

import (
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestValidateTag(t *testing.T) {
	for _, tag := range []Tag{
		{Key: "Team", Value: "Platform / SRE: a=b + c @x"},
		{Key: "Cost Center", Value: "12345"},
		{Key: "lower_case-1", Value: ""},
		{Key: strings.Repeat("k", MaxTagKeyLen), Value: "v"},
		{Key: "maxvalue", Value: strings.Repeat("v", MaxTagValueLen)},
	} {
		if err := ValidateTag(tag); err != nil {
			t.Errorf("%v rejected: %v", tag, err)
		}
	}
	for _, tc := range []struct {
		name string
		tag  Tag
	}{
		{"empty key", Tag{Key: ""}},
		{"key too long", Tag{Key: strings.Repeat("k", MaxTagKeyLen+1)}},
		{"value too long", Tag{Key: "k", Value: strings.Repeat("v", MaxTagValueLen+1)}},
		{"bad key character", Tag{Key: "bad#key"}},
		{"bad value character", Tag{Key: "k", Value: "bad#value"}},
		{"reserved key prefix", Tag{Key: "aws:team"}},
		{"reserved key prefix in another case", Tag{Key: "AWS:team"}},
		{"reserved value prefix", Tag{Key: "k", Value: "aws:value"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateTag(tc.tag); err == nil {
				t.Fatalf("%v accepted", tc.tag)
			}
		})
	}
}

func TestFakePolicyTags(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	p, err := f.CreatePolicy(ctx, a, "tagged", "/", describeOnly, "")
	if err != nil {
		t.Fatal(err)
	}
	if page, err := f.ListPolicyTags(ctx, a, p.ARN, "", 0); err != nil || len(page.Tags) != 0 || page.IsTruncated {
		t.Fatalf("fresh tags %+v %v", page, err)
	}
	tags := []Tag{{Key: "Team", Value: "platform"}, {Key: "env", Value: "prod"}}
	if err := f.TagPolicy(ctx, a, p.ARN, tags); err != nil {
		t.Fatal(err)
	}
	page, err := f.ListPolicyTags(ctx, a, p.ARN, "", 0)
	want := []Tag{{Key: "Team", Value: "platform"}, {Key: "env", Value: "prod"}}
	if err != nil || len(page.Tags) != 2 || page.Tags[0] != want[0] || page.Tags[1] != want[1] {
		t.Fatalf("tags %+v %v", page, err)
	}
	// A named key is overwritten; other keys stay.
	if err := f.TagPolicy(ctx, a, p.ARN, []Tag{{Key: "env", Value: "dev"}}); err != nil {
		t.Fatal(err)
	}
	if page, _ := f.ListPolicyTags(ctx, a, p.ARN, "", 0); len(page.Tags) != 2 || page.Tags[1].Value != "dev" {
		t.Fatalf("after overwrite %+v", page)
	}
	// Case is significant on a policy: a differently cased key is a new tag.
	if err := f.TagPolicy(ctx, a, p.ARN, []Tag{{Key: "ENV", Value: "PROD"}}); err != nil {
		t.Fatal(err)
	}
	if page, _ := f.ListPolicyTags(ctx, a, p.ARN, "", 0); len(page.Tags) != 3 {
		t.Fatalf("after case-different tag %+v", page)
	}
	// Untag ignores a key that is not attached.
	if err := f.UntagPolicy(ctx, a, p.ARN, []string{"Team", "missing"}); err != nil {
		t.Fatal(err)
	}
	if page, _ := f.ListPolicyTags(ctx, a, p.ARN, "", 0); len(page.Tags) != 2 || page.Tags[0].Key != "ENV" {
		t.Fatalf("after untag %+v", page)
	}
	// A missing policy is NoSuchEntity.
	other, _ := resource.Parse[resource.AccountID]("210987654321")
	err = f.TagPolicy(ctx, other, p.ARN, []Tag{{Key: "k", Value: "v"}})
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("cross-account tag %v", err)
	}
}

func TestFakePolicyTagErrors(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	p, err := f.CreatePolicy(ctx, a, "limits", "/", describeOnly, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.TagPolicy(ctx, a, p.ARN, []Tag{{Key: "bad#key"}}); err == nil {
		t.Fatal("invalid tag stored")
	}
	fill := make([]Tag, 50)
	for i := range fill {
		fill[i] = Tag{Key: "k" + strings.Repeat("x", i+1), Value: "v"}
	}
	if err := f.TagPolicy(ctx, a, p.ARN, fill); err != nil {
		t.Fatal(err)
	}
	err = f.TagPolicy(ctx, a, p.ARN, []Tag{{Key: "extra", Value: "v"}})
	if got := resource.CodeOf(err); got != resource.CodeResourceExhausted {
		t.Fatalf("51st tag error %v (%v)", err, got)
	}
	// Overwriting an attached key at the limit is not a new tag.
	if err := f.TagPolicy(ctx, a, p.ARN, []Tag{{Key: "k" + strings.Repeat("x", 50), Value: "new"}}); err != nil {
		t.Fatalf("overwrite at the limit: %v", err)
	}
	if err := f.UntagPolicy(ctx, a, p.ARN, nil); err == nil {
		t.Fatal("empty tag keys accepted")
	}
	if err := f.UntagPolicy(ctx, a, p.ARN, []string{""}); err == nil {
		t.Fatal("empty tag key accepted")
	}
}

func TestFakePolicyTagPages(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	p, err := f.CreatePolicy(ctx, a, "paged", "/", describeOnly, "")
	if err != nil {
		t.Fatal(err)
	}
	var tags []Tag
	for _, key := range []string{"a", "b", "c", "d", "e"} {
		tags = append(tags, Tag{Key: key, Value: key + "-value"})
	}
	if err := f.TagPolicy(ctx, a, p.ARN, tags); err != nil {
		t.Fatal(err)
	}
	var keys []string
	marker := ""
	for pages := 0; ; pages++ {
		if pages > 5 {
			t.Fatal("pagination did not end")
		}
		page, err := f.ListPolicyTags(ctx, a, p.ARN, marker, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, tag := range page.Tags {
			keys = append(keys, tag.Key)
		}
		if !page.IsTruncated {
			break
		}
		marker = page.Marker
	}
	if strings.Join(keys, "") != "abcde" {
		t.Fatalf("paged keys %v", keys)
	}
}
