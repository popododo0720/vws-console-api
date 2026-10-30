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
