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

func TestFakeListMFADevices(t *testing.T) {
	f := NewFake()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, name := range []string{"alice", "bob"} {
		if _, err := f.CreateUser(ctx, account, name, "/"); err != nil {
			t.Fatal(err)
		}
	}
	aliceA := f.AddMfaDevice(account, "alice-a")
	aliceB := f.AddMfaDevice(account, "alice-b")
	bobPhone := f.AddMfaDevice(account, "bob-phone")
	spare := f.AddMfaDevice(account, "spare-phone")
	enabled := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	f.Now = func() time.Time { return enabled }
	if err := f.AssignMfaDevice(account, aliceA, "alice", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := f.AssignMfaDevice(account, aliceB, "alice", enabled.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := f.AssignMfaDevice(account, bobPhone, "bob", enabled); err != nil {
		t.Fatal(err)
	}

	page, err := f.ListMFADevices(ctx, account, "alice", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.IsTruncated || len(page.Devices) != 2 {
		t.Fatalf("page %+v", page)
	}
	first, second := page.Devices[0], page.Devices[1]
	if first.SerialNumber != aliceA || second.SerialNumber != aliceB {
		t.Fatalf("serials %q %q, want %q %q", first.SerialNumber, second.SerialNumber, aliceA, aliceB)
	}
	for i, d := range page.Devices {
		if d.UserName != "alice" {
			t.Errorf("device %d user %q", i, d.UserName)
		}
	}
	if !first.Enabled.Equal(enabled) || !second.Enabled.Equal(enabled.Add(time.Hour)) {
		t.Errorf("enable dates %v %v", first.Enabled, second.Enabled)
	}
	for _, d := range page.Devices {
		if d.SerialNumber == bobPhone || d.SerialNumber == spare {
			t.Errorf("listed another user's or an unassigned device %+v", d)
		}
	}

	page, err = f.ListMFADevices(ctx, account, "alice", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !page.IsTruncated || page.Marker != aliceA || len(page.Devices) != 1 ||
		page.Devices[0].SerialNumber != aliceA {
		t.Fatalf("first page %+v, %v", page, err)
	}
	page, err = f.ListMFADevices(ctx, account, "alice", page.Marker, 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.IsTruncated || len(page.Devices) != 1 || page.Devices[0].SerialNumber != aliceB {
		t.Fatalf("second page %+v, %v", page, err)
	}

	if _, err := f.ListMFADevices(ctx, account, "nobody", "", 0); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("missing user: %v", err)
	}
}

func TestPageMFADevices(t *testing.T) {
	devices := []MFADevice{
		{SerialNumber: "c-phone", UserName: "alice"},
		{SerialNumber: "a-phone", UserName: "alice"},
		{SerialNumber: "b-phone", UserName: "alice"},
	}
	page := PageMFADevices(devices, "", 2)
	if !page.IsTruncated || page.Marker != "b-phone" || len(page.Devices) != 2 {
		t.Fatalf("first page %+v", page)
	}
	if page.Devices[0].SerialNumber != "a-phone" || page.Devices[1].SerialNumber != "b-phone" {
		t.Fatalf("first page serials %+v", page.Devices)
	}
	if devices[0].SerialNumber != "c-phone" {
		t.Errorf("input was changed: %+v", devices)
	}
	page = PageMFADevices(devices, "b-phone", 2)
	if page.IsTruncated || len(page.Devices) != 1 || page.Devices[0].SerialNumber != "c-phone" {
		t.Fatalf("rest page %+v", page)
	}
	page = PageMFADevices(devices, "z-phone", 2)
	if page.IsTruncated || len(page.Devices) != 0 {
		t.Fatalf("page after the last serial %+v", page)
	}
	page = PageMFADevices(devices, "", 0)
	if page.IsTruncated || len(page.Devices) != 3 {
		t.Fatalf("default page %+v", page)
	}
}
