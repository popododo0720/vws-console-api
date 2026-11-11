package grpcclient

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestRebootIsUnsupportedOverGRPC pins that RebootInstances is refused, not
// answered as done, while the compute API this client speaks has no reboot.
func TestRebootIsUnsupportedOverGRPC(t *testing.T) {
	id, err := resource.Parse[resource.InstanceID]("i-01234567")
	if err != nil {
		t.Fatal(err)
	}
	_, err = computeClient{}.RebootInstances(t.Context(), backend.Mutation{}, resource.RebootInstancesRequest{
		IDs: []resource.InstanceID{id},
	})
	if !resource.IsUnsupported(resource.AsError(err)) {
		t.Fatalf("err %v, want UnsupportedOperation", err)
	}
}
