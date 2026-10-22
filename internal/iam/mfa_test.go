package iam

import (
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// AWS GetMFADevice accepts only FIDO security key serial numbers, and the fake
// keeps no FIDO keys, so every serial number is NoSuchEntity: a u2f/ key, an
// unassigned or enabled virtual mfa/ device, and a renamed owner's device.
func TestFakeGetMFADevice(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	f.Now = func() time.Time { return now }
	if _, err := f.CreateUser(ctx, a, "alice", "/"); err != nil {
		t.Fatal(err)
	}
	virtual := f.AddMfaDevice(a, "alice-phone")
	notFound := func(name string, acct resource.AccountID, serial string) {
		t.Helper()
		dev, err := f.GetMFADevice(ctx, acct, serial)
		if resource.CodeOf(err) != resource.CodeNotFound || err.Error() != MFADeviceNotFound().Error() {
			t.Errorf("%s: %+v %v, want NoSuchEntity", name, dev, err)
		}
	}
	notFound("unassigned virtual device", a, virtual)
	if err := f.AssignMfaDevice(a, virtual, "alice", now); err != nil {
		t.Fatal(err)
	}
	// The device is enabled for alice, so it is listed as assigned.
	page, err := f.ListVirtualMFADevices(ctx, a, MFADeviceAssignmentAssigned, "", 100)
	if err != nil || len(page.Devices) != 1 || page.Devices[0].SerialNumber != virtual {
		t.Fatalf("assigned devices %+v %v", page, err)
	}
	notFound("enabled virtual device", a, virtual)
	notFound("FIDO security key", a, "arn:vws:iam::"+a.String()+":u2f/alice/testFidoKey-R1234")
	notFound("unknown serial", a, "arn:vws:iam::"+a.String()+":mfa/ghost")
	if err := f.UpdateUser(ctx, a, "alice", "", "alicia", ""); err != nil {
		t.Fatal(err)
	}
	notFound("renamed owner", a, virtual)
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	notFound("other account", other, virtual)

	if err := f.AssignMfaDevice(a, virtual, "nobody", now); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("enable for a missing user: %v", err)
	}
	ghost := "arn:vws:iam::" + a.String() + ":mfa/ghost"
	if err := f.AssignMfaDevice(a, ghost, "alicia", now); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("enable a missing device: %v", err)
	}
}
