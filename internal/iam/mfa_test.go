package iam

import (
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestFakeGetMFADevice(t *testing.T) {
	ctx := t.Context()
	a := account(t)
	f := NewFake()
	f.Now = func() time.Time { return now }
	u, err := f.CreateUser(ctx, a, "alice", "/")
	if err != nil {
		t.Fatal(err)
	}
	serial := f.AddMfaDevice(a, "alice-phone")

	// An unassigned device is not a device GetMFADevice answers for.
	if _, err := f.GetMFADevice(ctx, a, serial); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("unassigned device: %v", err)
	}
	if err := f.AssignMfaDevice(a, serial, "alice", now); err != nil {
		t.Fatal(err)
	}
	dev, err := f.GetMFADevice(ctx, a, serial)
	if err != nil {
		t.Fatal(err)
	}
	if dev.SerialNumber != serial || dev.UserName != "alice" || dev.UserARN != u.ARN ||
		!dev.Enabled.Equal(now) {
		t.Fatalf("enabled device %+v", dev)
	}
	// A rename moves the device's owner with the user.
	if err := f.UpdateUser(ctx, a, "alice", "", "alicia", ""); err != nil {
		t.Fatal(err)
	}
	dev, err = f.GetMFADevice(ctx, a, serial)
	if err != nil {
		t.Fatal(err)
	}
	if dev.UserName != "alicia" || dev.UserARN != iamARN(a, "user", "/", "alicia") {
		t.Fatalf("renamed owner %+v", dev)
	}

	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		acct   resource.AccountID
		serial string
	}{
		{"unknown serial", a, "arn:vws:iam::" + a.String() + ":mfa/ghost"},
		{"other account", other, serial},
	} {
		if _, err := f.GetMFADevice(ctx, tc.acct, tc.serial); resource.CodeOf(err) != resource.CodeNotFound {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if err := f.AssignMfaDevice(a, serial, "nobody", now); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("enable for a missing user: %v", err)
	}
	ghost := "arn:vws:iam::" + a.String() + ":mfa/ghost"
	if err := f.AssignMfaDevice(a, ghost, "alice", now); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("enable a missing device: %v", err)
	}
}
