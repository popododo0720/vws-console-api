package iam

import (
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestFakeMFADeviceTags(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	serial := f.AddMfaDevice(a, "alice-phone")
	if page, err := f.ListMFADeviceTags(ctx, a, serial, "", 0); err != nil || len(page.Tags) != 0 || page.IsTruncated {
		t.Fatalf("fresh tags %+v %v", page, err)
	}
	tags := []Tag{{Key: "Team", Value: "platform"}, {Key: "env", Value: "prod"}}
	if err := f.TagMFADevice(ctx, a, serial, tags); err != nil {
		t.Fatal(err)
	}
	page, err := f.ListMFADeviceTags(ctx, a, serial, "", 0)
	want := []Tag{{Key: "Team", Value: "platform"}, {Key: "env", Value: "prod"}}
	if err != nil || len(page.Tags) != 2 || page.Tags[0] != want[0] || page.Tags[1] != want[1] {
		t.Fatalf("tags %+v %v", page, err)
	}
	// A named key is overwritten; other keys stay.
	if err := f.TagMFADevice(ctx, a, serial, []Tag{{Key: "env", Value: "dev"}}); err != nil {
		t.Fatal(err)
	}
	if page, _ := f.ListMFADeviceTags(ctx, a, serial, "", 0); len(page.Tags) != 2 || page.Tags[1].Value != "dev" {
		t.Fatalf("after overwrite %+v", page)
	}
	// Case is significant on a device: a differently cased key is a new tag.
	if err := f.TagMFADevice(ctx, a, serial, []Tag{{Key: "ENV", Value: "PROD"}}); err != nil {
		t.Fatal(err)
	}
	if page, _ := f.ListMFADeviceTags(ctx, a, serial, "", 0); len(page.Tags) != 3 {
		t.Fatalf("after case-different tag %+v", page)
	}
	// Untag ignores a key that is not attached.
	if err := f.UntagMFADevice(ctx, a, serial, []string{"Team", "missing"}); err != nil {
		t.Fatal(err)
	}
	if page, _ := f.ListMFADeviceTags(ctx, a, serial, "", 0); len(page.Tags) != 2 || page.Tags[0].Key != "ENV" {
		t.Fatalf("after untag %+v", page)
	}
	// A device that does not exist is NoSuchEntity, on every action.
	ghost := "arn:vws:iam::" + a.String() + ":mfa/ghost"
	err = f.TagMFADevice(ctx, a, ghost, []Tag{{Key: "k", Value: "v"}})
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("tag missing device %v", err)
	}
	if err := f.UntagMFADevice(ctx, a, ghost, []string{"k"}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("untag missing device %v", err)
	}
	if _, err := f.ListMFADeviceTags(ctx, a, ghost, "", 0); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("list missing device %v", err)
	}
	// A device belongs to one account.
	other, _ := resource.Parse[resource.AccountID]("210987654321")
	err = f.TagMFADevice(ctx, other, serial, []Tag{{Key: "k", Value: "v"}})
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("cross-account tag %v", err)
	}
}

func TestFakeMFADeviceTagErrors(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	serial := f.AddMfaDevice(a, "limits-phone")
	if err := f.TagMFADevice(ctx, a, serial, []Tag{{Key: "bad#key"}}); err == nil {
		t.Fatal("invalid tag stored")
	}
	fill := make([]Tag, 50)
	for i := range fill {
		fill[i] = Tag{Key: "k" + strings.Repeat("x", i+1), Value: "v"}
	}
	if err := f.TagMFADevice(ctx, a, serial, fill); err != nil {
		t.Fatal(err)
	}
	err := f.TagMFADevice(ctx, a, serial, []Tag{{Key: "extra", Value: "v"}})
	if got := resource.CodeOf(err); got != resource.CodeResourceExhausted {
		t.Fatalf("51st tag error %v (%v)", err, got)
	}
	// Overwriting an attached key at the limit is not a new tag.
	if err := f.TagMFADevice(ctx, a, serial, []Tag{{Key: "k" + strings.Repeat("x", 50), Value: "new"}}); err != nil {
		t.Fatalf("overwrite at the limit: %v", err)
	}
	if err := f.UntagMFADevice(ctx, a, serial, nil); err == nil {
		t.Fatal("empty tag keys accepted")
	}
	if err := f.UntagMFADevice(ctx, a, serial, []string{""}); err == nil {
		t.Fatal("empty tag key accepted")
	}
}

func TestFakeMFADeviceTagPages(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	serial := f.AddMfaDevice(a, "paged-phone")
	var tags []Tag
	for _, key := range []string{"a", "b", "c", "d", "e"} {
		tags = append(tags, Tag{Key: key, Value: key + "-value"})
	}
	if err := f.TagMFADevice(ctx, a, serial, tags); err != nil {
		t.Fatal(err)
	}
	var keys []string
	marker := ""
	for pages := 0; ; pages++ {
		if pages > 5 {
			t.Fatal("pagination did not end")
		}
		page, err := f.ListMFADeviceTags(ctx, a, serial, marker, 2)
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

// AddMfaDevice returns the serial number the AWS Query API calls SerialNumber.
func TestAddMfaDeviceSerial(t *testing.T) {
	a := account(t)
	f := NewFake()
	serial := f.AddMfaDevice(a, "alice-phone")
	if want := "arn:vws:iam::" + a.String() + ":mfa/alice-phone"; serial != want {
		t.Fatalf("serial %q, want %q", serial, want)
	}
}
