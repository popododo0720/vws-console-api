package backendtest

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// MFADeviceHarness builds a fresh, empty iam.Directory for one
// IAMCreateMFADeviceTagRefusals row, and reports whether that Directory has
// created any virtual MFA device since.
type MFADeviceHarness func(t *testing.T) (dir iam.Directory, created func() bool)

// IAMCreateMFADeviceTagRefusals runs the #850 contract of the tags
// CreateVirtualMFADevice refuses, which the in-memory fake and the vws-iam
// client must answer alike: more than MaxTags tags is LimitExceeded, a bad
// tag or an aws: key or value is InvalidInput on Tags, and a refused create
// leaves no device behind.
func IAMCreateMFADeviceTagRefusals(t *testing.T, newDir MFADeviceHarness) {
	t.Helper()
	tooMany := make([]iam.Tag, iam.MaxTags+1)
	for i := range tooMany {
		tooMany[i] = iam.Tag{Key: "k" + strconv.Itoa(i)}
	}
	for _, row := range []struct {
		name string
		tags []iam.Tag
		code resource.Code
		msg  string
	}{
		{"51 tags", tooMany, resource.CodeResourceExhausted, iam.MFADeviceTagsExceeded().Error()},
		{"bad key", []iam.Tag{{Key: "bad#key", Value: "v"}}, resource.CodeInvalidArgument, "tags.member.key"},
		{"aws: key", []iam.Tag{{Key: "aws:owner", Value: "v"}}, resource.CodeInvalidArgument, "reserved prefix"},
		{"aws: value", []iam.Tag{{Key: "team", Value: "aws:x"}}, resource.CodeInvalidArgument, "reserved prefix"},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir, created := newDir(t)
			_, err := dir.CreateVirtualMFADevice(context.Background(), iamAccount(), "refused", "/", row.tags)
			if resource.CodeOf(err) != row.code || !strings.Contains(err.Error(), row.msg) {
				t.Fatalf("got %v, want %v %q", err, row.code, row.msg)
			}
			var e *resource.Error
			if row.code == resource.CodeInvalidArgument && (!errors.As(err, &e) || e.Field != "Tags") {
				t.Errorf("field of %v is not Tags, so it is not InvalidInput", err)
			}
			if created() {
				t.Error("a refused create left a device")
			}
		})
	}
}
