package iam_test

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
)

// #342: every Admin call of the fake bound to an AuthorizedPrincipal refuses the
// zero value and a moved entity, and serves the authorized one.
func TestFakeAuthorizedPrincipalContract(t *testing.T) {
	backendtest.IAMAuthorizedPrincipal(t, func(*testing.T) (iam.Directory, backendtest.PolicySeeder) {
		return iam.NewFake(), nil
	}, backendtest.ServesAll)
}

// #358: the fake resolves a named user, group or role to its ARN and unique
// ID only, as the surface authorizes on it.
func TestFakeResolverContract(t *testing.T) {
	backendtest.IAMResolver(t, func(*testing.T) iam.Directory { return iam.NewFake() }, backendtest.ServesAll)
}
