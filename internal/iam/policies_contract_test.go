package iam_test

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// #314 bundle 3: the fake answers the user and group policy contract.
func TestFakeEntityPolicyContract(t *testing.T) {
	backendtest.IAMEntityPolicies(t, func(*testing.T) (iam.Directory, backendtest.PolicySeeder) {
		f := iam.NewFake()
		account, err := resource.Parse[resource.AccountID]("123456789012")
		if err != nil {
			t.Fatal(err)
		}
		seed := func(t *testing.T, name, path string) string {
			t.Helper()
			p, err := f.CreatePolicy(context.Background(), account, name, path,
				`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`, "")
			if err != nil {
				t.Fatalf("seed CreatePolicy %s: %v", name, err)
			}
			return p.ARN
		}
		return f, seed
	})
}
