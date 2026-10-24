package iamclient

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
)

// #314: STSAdmin over a vws-iam UserService and GroupService answers the user
// and group contract as the fake does.
func TestGRPCUserAndGroupContract(t *testing.T) {
	backendtest.IAMUsersAndGroups(t, func(t *testing.T) iam.Directory {
		c, _ := dirHarness(t)
		return STSAdmin{Client: c}
	})
}
