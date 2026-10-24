package iam_test

import (
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
)

// #314 bundle 2: the fake answers the access key contract.
func TestFakeAccessKeyContract(t *testing.T) {
	backendtest.IAMAccessKeys(t, func(*testing.T) iam.Directory { return iam.NewFake() })
}
