package grpcclient

import (
	"context"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestRunInstancesRejectsTagsBeforeCreate pins #197 for a launch the backend
// refuses after the image check: tags that do not fit the compute labels are
// rejected before the boot volume exists, and a retry repeats the refusal.
func TestRunInstancesRejectsTagsBeforeCreate(t *testing.T) {
	sub, err := resource.Parse[resource.SubnetID]("subnet-01234567")
	if err != nil {
		t.Fatal(err)
	}
	tags := map[string]string{}
	for i := 0; i < 20; i++ {
		tags[strings.Repeat("K", 127)+string(rune('a'+i))] = strings.Repeat("v", 256)
	}
	boot, client := startRegional(t)
	for i := 0; i < 2; i++ {
		_, err = client.RunInstances(context.Background(), backend.Mutation{
			Scope: backend.Scope{Account: mustAccount(t)}, Key: "refused-tags", Fingerprint: "fp",
		}, resource.RunInstancesRequest{
			ImageID: mustImage(t, catalogAMI), InstanceType: "vws.small", SubnetID: sub, Count: 1, Tags: tags,
		})
		if resource.CodeOf(err) != resource.CodeInvalidArgument {
			t.Fatalf("try %d: err %v, want invalid argument", i, err)
		}
	}
	boot.mu.Lock()
	defer boot.mu.Unlock()
	if boot.volumes != 0 || boot.instances != 0 {
		t.Fatalf("refused launch created volumes %d instances %d", boot.volumes, boot.instances)
	}
}
