package iam_test

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
)

// #342: every Admin call of the fake bound to an AuthorizedARN refuses the
// zero value and a moved entity, and serves the authorized one.
func TestFakeAuthorizedARNContract(t *testing.T) {
	backendtest.IAMAuthorizedARN(t, func(*testing.T) (iam.Admin, backendtest.PolicySeeder) {
		return iam.NewFake(), nil
	}, backendtest.ServesAll)
}
