package regionapi

import (
	"reflect"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestErrorRefinementsRoundTrip(t *testing.T) {
	for _, want := range []*resource.Error{
		resource.Unsupported("filter", "unsupported filter"),
		resource.MissingParameter("id", "required"),
		resource.InvalidCombination("id", "combination"),
		resource.TagLimitExceeded("tags", "too many"),
		resource.InvalidTaggedID("bad-id"),
		resource.AttachmentLimitExceeded("too many"),
		resource.DuplicatePermission("sg-0123456789abcdef0"),
		resource.RulesPerSecurityGroupLimitExceeded("sg-0123456789abcdef0"),
		resource.PermissionNotFound("sg-0123456789abcdef0"),
		resource.BucketAlreadyOwned("bucket"),
		resource.BucketDeleting("bucket"),
	} {
		t.Run(want.Message, func(t *testing.T) {
			set := fake.New(fake.Options{}).Set()
			set.Compute = errorCompute{Compute: set.Compute, err: want}
			c, _ := loopback(t, config(set))
			var page resource.Page[resource.Instance]
			got := c.Call(t.Context(), "Compute", "DescribeInstances", testScope(t), resource.InstanceQuery{}, &page)
			if !reflect.DeepEqual(resource.AsError(got), want) {
				t.Fatalf("refinement changed: got %#v, want %#v", resource.AsError(got), want)
			}
			if resource.IsUnsupported(resource.AsError(got)) != resource.IsUnsupported(want) {
				t.Fatal("unsupported classification changed")
			}
		})
	}
}
