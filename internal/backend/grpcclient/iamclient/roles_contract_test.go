package iamclient

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
)

// #573: STSAdmin over a vws-iam RoleService answers the role lifecycle
// contract as the fake does.
func TestGRPCRoleContract(t *testing.T) {
	backendtest.IAMRoles(t, func(t *testing.T) iam.Directory {
		c, _ := dirHarness(t)
		return STSAdmin{Client: c}
	})
}
