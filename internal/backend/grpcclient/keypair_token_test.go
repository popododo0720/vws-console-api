package grpcclient

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestCreateAfterDeleteUnderTheSameTokenIsANewKey is #268 against a compute
// stub that keeps every request id it has seen, as vws-compute does. After
// the name is deleted, a create under the same client token must not hit the
// retained record of the first create: it is a new request and a new key
// pair with an unrelated private key. A retry while that key pair lives is
// still InvalidKeyPair.Duplicate with no private key.
func TestCreateAfterDeleteUnderTheSameTokenIsANewKey(t *testing.T) {
	ctx := context.Background()
	client, world := dialKeyWorld(t)
	scope := backend.Scope{Account: mustAccount(t)}
	m := backend.Mutation{Scope: scope, Key: "same-token", Fingerprint: "same-request"}
	req := resource.CreateKeyPairRequest{Name: "deploy", Type: resource.KeyTypeEd25519}

	first, err := client.CreateKeyPair(ctx, m, req)
	if err != nil || len(first.Items) != 1 || first.Items[0].Material == "" {
		t.Fatalf("first create: %v %+v", err, first.Items)
	}
	del := backend.Mutation{Scope: scope, Key: "delete-token", Fingerprint: "delete-request"}
	if _, err := client.DeleteKeyPair(ctx, del, resource.DeleteKeyPairRequest{Name: "deploy"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	second, err := client.CreateKeyPair(ctx, m, req)
	if err != nil || len(second.Items) != 1 || second.Items[0].Material == "" {
		t.Fatalf("create after delete under the same token: want a new key pair, got %v %+v", err, second.Items)
	}
	if second.Items[0].Material == first.Items[0].Material || second.Items[0].Fingerprint == first.Items[0].Fingerprint {
		t.Fatal("create after delete returned the first private key")
	}
	if len(world.keys) != 1 || len(world.requests) != 2 {
		t.Fatalf("compute holds %d key pairs and %d request ids, want 1 and 2", len(world.keys), len(world.requests))
	}
	again, err := client.CreateKeyPair(ctx, m, req)
	requireDuplicate(t, "retry while the new key pair lives", again, err)
}
