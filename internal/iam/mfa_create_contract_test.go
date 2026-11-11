package iam_test

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// #850: the fake refuses the create-time tags of the contract and stores no
// device for a refused create.
func TestFakeCreateMFADeviceTagContract(t *testing.T) {
	backendtest.IAMCreateMFADeviceTagRefusals(t, func(t *testing.T) (iam.Directory, func() bool) {
		f := iam.NewFake()
		return f, func() bool {
			a, err := resource.Parse[resource.AccountID]("123456789012")
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.ListMFADeviceTags(context.Background(), a, iam.VirtualMFADeviceSerial(a, "/", "refused"), "", 0)
			return err == nil
		}
	})
}
