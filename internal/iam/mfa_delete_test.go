package iam

import (
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestFakeDeleteVirtualMFADevice(t *testing.T) {
	ctx := t.Context()
	f := NewFake()
	a := account(t)
	spare := f.AddMfaDevice(a, "spare-phone")
	if err := f.TagMFADevice(ctx, a, spare, []Tag{{Key: "k", Value: "v"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.DeleteVirtualMFADevice(ctx, a, spare); err != nil {
		t.Fatal(err)
	}
	// The device and its tags are gone, and deleting again is NoSuchEntity.
	if _, err := f.ListMFADeviceTags(ctx, a, spare, "", 0); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("tags of a deleted device: %v", err)
	}
	if err := f.DeleteVirtualMFADevice(ctx, a, spare); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("second delete: %v", err)
	}

	if _, err := f.CreateUser(ctx, a, "alice", "/"); err != nil {
		t.Fatal(err)
	}
	enabled := f.AddMfaDevice(a, "alice-phone")
	if err := f.AssignMfaDevice(a, enabled, "alice", time.Time{}); err != nil {
		t.Fatal(err)
	}
	err := f.DeleteVirtualMFADevice(ctx, a, enabled)
	if resource.CodeOf(err) != resource.CodeConflict || IsChanged(err) {
		t.Fatalf("enabled device: %v, want DeleteConflict", err)
	}
	page, err := f.ListVirtualMFADevices(ctx, a, MFADeviceAssignmentAny, "", 0)
	if err != nil || len(page.Devices) != 1 || page.Devices[0].SerialNumber != enabled {
		t.Fatalf("enabled device not kept: %v %v", page, err)
	}
}
