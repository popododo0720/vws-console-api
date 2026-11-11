package iam_test

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
)

// #573: the fake answers the role lifecycle contract.
func TestFakeRoleContract(t *testing.T) {
	backendtest.IAMRoles(t, func(*testing.T) iam.Directory { return iam.NewFake() })
}
