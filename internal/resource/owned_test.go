package resource

import (
	"fmt"
	"testing"
)

// TestBucketAlreadyOwned pins the #315 marker: an owned-name create is
// CodeAlreadyExists, survives wrapping, and a plain AlreadyExists is not it.
func TestBucketAlreadyOwned(t *testing.T) {
	e := BucketAlreadyOwned("logs")
	if e.Code != CodeAlreadyExists || e.Kind != KindBucket || e.ID != "logs" || e.Message != BucketOwnedMessage {
		t.Fatalf("owned = %+v", e)
	}
	if !OwnedByCaller(fmt.Errorf("wrapped: %w", e)) {
		t.Fatal("wrapped owned error lost its marker")
	}
	if OwnedByCaller(AlreadyExists(KindBucket, "logs")) || OwnedByCaller(nil) {
		t.Fatal("another account's name reads as owned")
	}
	if c := e.WithCause(fmt.Errorf("x")); !OwnedByCaller(c) {
		t.Fatal("WithCause dropped the marker")
	}
}
