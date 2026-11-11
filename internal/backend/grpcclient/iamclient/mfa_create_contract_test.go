package iamclient

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
)

// #850: STSAdmin refuses the create-time tags of the contract as the fake
// does, before any CreateVirtualMfaDevice reaches vws-iam, so no device is
// created.
func TestGRPCCreateMFADeviceTagContract(t *testing.T) {
	backendtest.IAMCreateMFADeviceTagRefusals(t, func(t *testing.T) (iam.Directory, func() bool) {
		c, s := harness(t)
		return STSAdmin{Client: c}, func() bool { return len(s.createMfa) != 0 }
	})
}
