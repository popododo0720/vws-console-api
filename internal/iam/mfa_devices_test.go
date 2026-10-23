package iam

import (
	"context"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestFakeListVirtualMFADevices(t *testing.T) {
	f := NewFake()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := f.CreateUser(ctx, account, "alice", "/eng/"); err != nil {
		t.Fatal(err)
	}
	assigned := f.AddMfaDevice(account, "alice-phone")
	spare := f.AddMfaDevice(account, "spare-phone")
	enabled := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	if err := f.AssignMfaDevice(account, assigned, "alice", enabled); err != nil {
		t.Fatal(err)
	}

	page, err := f.ListVirtualMFADevices(ctx, account, MFADeviceAssignmentAny, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Devices) != 2 || page.IsTruncated {
		t.Fatalf("page %+v", page)
	}
	first, second := page.Devices[0], page.Devices[1]
	if first.SerialNumber != assigned || second.SerialNumber != spare {
		t.Fatalf("serials %q %q, want %q %q", first.SerialNumber, second.SerialNumber, assigned, spare)
	}
	if first.User == nil || first.User.Name != "alice" || first.User.Path != "/eng/" ||
		first.User.ARN != "arn:vws:iam::123456789012:user/eng/alice" {
		t.Errorf("assigned user %+v", first.User)
	}
	if !first.EnableDate.Equal(enabled) {
		t.Errorf("enable date %v, want %v", first.EnableDate, enabled)
	}
	if second.User != nil || !second.EnableDate.IsZero() {
		t.Errorf("unassigned device %+v", second)
	}

	page, err = f.ListVirtualMFADevices(ctx, account, MFADeviceAssignmentAssigned, "", 0)
	if err != nil || len(page.Devices) != 1 || page.Devices[0].SerialNumber != assigned {
		t.Fatalf("assigned page %+v, %v", page, err)
	}
	page, err = f.ListVirtualMFADevices(ctx, account, MFADeviceAssignmentUnassigned, "", 0)
	if err != nil || len(page.Devices) != 1 || page.Devices[0].SerialNumber != spare {
		t.Fatalf("unassigned page %+v, %v", page, err)
	}
	page, err = f.ListVirtualMFADevices(ctx, account, MFADeviceAssignmentAny, "", 1)
	if err != nil || !page.IsTruncated || page.Marker != assigned || len(page.Devices) != 1 {
		t.Fatalf("first page %+v, %v", page, err)
	}
	page, err = f.ListVirtualMFADevices(ctx, account, MFADeviceAssignmentAny, page.Marker, 1)
	if err != nil || page.IsTruncated || len(page.Devices) != 1 || page.Devices[0].SerialNumber != spare {
		t.Fatalf("second page %+v, %v", page, err)
	}
}

func TestFakeAssignMfaDeviceNeedsAUser(t *testing.T) {
	f := NewFake()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	serial := f.AddMfaDevice(account, "orphan")
	err = f.AssignMfaDevice(account, serial, "nobody", time.Time{})
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("assign to a missing user: %v", err)
	}
}

func TestFakeAssignedMfaDeviceFollowsUserMutations(t *testing.T) {
	f := NewFake()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := f.CreateUser(ctx, account, "alice", "/old/"); err != nil {
		t.Fatal(err)
	}
	serial := f.AddMfaDevice(account, "alice-phone")
	if err := f.AssignMfaDevice(account, serial, "alice", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := f.DeleteUser(ctx, account, "alice", ""); resource.CodeOf(err) != resource.CodeConflict {
		t.Fatalf("delete of a user with an assigned device: %v", err)
	}
	if err := f.UpdateUser(ctx, account, "alice", "/new/", "alicia", ""); err != nil {
		t.Fatal(err)
	}
	page, err := f.ListVirtualMFADevices(ctx, account, MFADeviceAssignmentAssigned, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Devices) != 1 || page.Devices[0].User == nil {
		t.Fatalf("page %+v", page)
	}
	user := page.Devices[0].User
	if user.Name != "alicia" || user.Path != "/new/" || user.ARN != "arn:vws:iam::123456789012:user/new/alicia" {
		t.Errorf("user after rename %+v", user)
	}
}
