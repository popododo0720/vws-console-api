package iamclient

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
)

// #314 bundle 3: STSAdmin over vws-iam UserService, GroupService and
// PolicyService answers the user and group policy contract as the fake does.
func TestGRPCEntityPolicyContract(t *testing.T) {
	backendtest.IAMEntityPolicies(t, func(t *testing.T) (iam.Directory, backendtest.PolicySeeder) {
		c, d := dirHarness(t)
		return STSAdmin{Client: c}, func(_ *testing.T, name, path string) string { return d.seedPolicy(name, path) }
	})
}
