package iamclient

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
)

// #314 bundle 2: STSAdmin over a vws-iam AccessKeyService answers the access
// key contract as the fake does.
func TestGRPCAccessKeyContract(t *testing.T) {
	backendtest.IAMAccessKeys(t, func(t *testing.T) iam.Directory {
		c, _ := dirHarness(t)
		return STSAdmin{Client: c}
	})
}
