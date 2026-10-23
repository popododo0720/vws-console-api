package backendtest

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// BucketCreate is the #315 table. S3 CreateBucket on a name the caller
// already owns is BucketAlreadyOwnedByYou and changes nothing; a name
// another account holds is BucketAlreadyExists. A name freed by
// DeleteBucket can be created again, and the new bucket exists. The fake and
// the gRPC client run this one table.
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html
func BucketCreate(t *testing.T, newSet Harness) {
	t.Helper()
	ctx := context.Background()
	set := newSet()
	owner, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	name, err := resource.Parse[resource.BucketName]("owned-twice")
	if err != nil {
		t.Fatal(err)
	}
	mine, theirs := backend.Scope{Account: owner}, backend.Scope{Account: other}
	first, err := set.Storage.CreateBucket(ctx, mine, name)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	for _, step := range []struct {
		label string
		scope backend.Scope
		owned bool
	}{
		{"owner creates again", mine, true},
		{"another account creates the owned name", theirs, false},
		{"owner creates a third time", mine, true},
	} {
		_, err := set.Storage.CreateBucket(ctx, step.scope, name)
		if resource.CodeOf(err) != resource.CodeAlreadyExists || resource.OwnedByCaller(err) != step.owned {
			t.Fatalf("%s: err %v, want AlreadyExists with owned=%v", step.label, err, step.owned)
		}
		got, err := set.Storage.GetBucket(ctx, mine, name)
		if err != nil || got.OwnerID != owner || got.CreationDate != first.CreationDate {
			t.Fatalf("%s changed the bucket: %+v, %v (was %+v)", step.label, got, err, first)
		}
	}
	if err := set.Storage.DeleteBucket(ctx, mine, name); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := set.Storage.CreateBucket(ctx, mine, name); err != nil {
		t.Fatalf("create after delete: %v", err)
	}
	if _, err := set.Storage.GetBucket(ctx, mine, name); err != nil {
		t.Fatalf("bucket created after delete is missing: %v", err)
	}
	if _, err := set.Storage.CreateBucket(ctx, mine, name); !resource.OwnedByCaller(err) {
		t.Fatalf("create after re-create: %v, want owned", err)
	}
}
