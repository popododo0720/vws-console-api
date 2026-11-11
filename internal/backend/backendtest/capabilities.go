package backendtest

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func requireCapabilities(
	t *testing.T, caps resource.RegionCapabilities, actions []resource.Action, reads []resource.ReadAction,
) {
	t.Helper()
	check := func(key string, cap resource.ActionCapability) {
		t.Helper()
		if cap.State != resource.ActionSupported && cap.State != resource.ActionPartial {
			reason := cap.Reason
			if reason == "" {
				reason = "region declares an empty read"
			}
			t.Skipf("%s: %s (%s)", key, reason, cap.State)
		}
	}
	for _, action := range actions {
		check(action.CapabilityKey(), caps.Mutation(action))
	}
	for _, read := range reads {
		check(read.CapabilityKey(), caps.Read(read))
	}
}
