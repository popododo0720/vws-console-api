package resource

import "testing"

// TestDuplicatePermissionIsAlreadyExists pins the code and the marker that
// keeps a duplicate rule apart from a duplicate group name (#272).
func TestDuplicatePermissionIsAlreadyExists(t *testing.T) {
	const id = "sg-0123456789abcdef0"
	err := DuplicatePermission(id)
	if err.Code != CodeAlreadyExists || err.Kind != KindSecurityGroup || err.ID != id {
		t.Fatalf("duplicate permission = %+v", err)
	}
	if !IsDuplicatePermission(err) {
		t.Fatal("DuplicatePermission is not a duplicate permission")
	}
	if IsDuplicatePermission(AlreadyExists(KindSecurityGroup, id)) {
		t.Fatal("a duplicate group name is a duplicate permission")
	}
}

// TestPermissionNotFoundIsNotFound pins the code and the marker that keeps a
// missing rule apart from a missing group (#272).
func TestPermissionNotFoundIsNotFound(t *testing.T) {
	const id = "sg-0123456789abcdef0"
	err := PermissionNotFound(id)
	if err.Code != CodeNotFound || err.Kind != KindSecurityGroup || err.ID != id {
		t.Fatalf("permission not found = %+v", err)
	}
	if !IsPermissionNotFound(err) {
		t.Fatal("PermissionNotFound is not a missing permission")
	}
	if IsPermissionNotFound(NotFound(KindSecurityGroup, id)) {
		t.Fatal("a missing group is a missing permission")
	}
}
