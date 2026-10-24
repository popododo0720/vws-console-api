package iam_test

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
)

// #314: the fake answers the user and group contract the vws-iam client is
// held to.
func TestFakeUserAndGroupContract(t *testing.T) {
	backendtest.IAMUsersAndGroups(t, func(*testing.T) iam.Directory { return iam.NewFake() })
}
