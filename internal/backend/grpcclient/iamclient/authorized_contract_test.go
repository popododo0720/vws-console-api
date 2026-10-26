package iamclient

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
)

// #342: STSAdmin over vws-iam answers the AuthorizedPrincipal contract as the fake
// does. The directory serves users, groups, access keys and the user and
// group policies; every other bound call (login profiles, MFA devices,
// roles and their policies) is checked for the zero AuthorizedPrincipal, which it
// refuses before it sends anything.
func TestGRPCAuthorizedPrincipalContract(t *testing.T) {
	backendtest.IAMAuthorizedPrincipal(t, func(t *testing.T) (iam.Directory, backendtest.PolicySeeder) {
		c, d := dirHarness(t)
		seed := func(t *testing.T, name, path string) string {
			t.Helper()
			return d.seedPolicy(name, path)
		}
		return countingAdmin{STSAdmin{Client: c}, d}, seed
	}, backendtest.ServesEntityPolicies)
}

// countingAdmin is STSAdmin with the number of requests its directory got.
type countingAdmin struct {
	STSAdmin
	d *directory
}

func (a countingAdmin) Calls() int {
	a.d.mu.Lock()
	defer a.d.mu.Unlock()
	n := 0
	for _, reqs := range a.d.calls {
		n += len(reqs)
	}
	return n
}

// #358: STSAdmin resolves a named user or group as the fake does, with one
// GroupService.GetGroup and no member read for a group. Roles are not
// created over vws-iam, so the role row runs on the fake only.
func TestGRPCResolverContract(t *testing.T) {
	backendtest.IAMResolver(t, func(t *testing.T) iam.Directory {
		c, d := dirHarness(t)
		return countingAdmin{STSAdmin{Client: c}, d}
	}, 0)
}
