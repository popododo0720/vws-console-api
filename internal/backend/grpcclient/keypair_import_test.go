package grpcclient

import (
	"context"
	"crypto/rand"
	"testing"

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sshkey"
)

// TestKeyImportContract runs the #279 ImportKeyPair table over the gRPC
// client against keyWorld, which keeps every request id it has seen and
// claims key pair ids atomically, as vws-compute does.
func TestKeyImportContract(t *testing.T) {
	backendtest.KeyImport(t, func() backend.Set {
		client, _ := dialKeyWorld(t)
		return backend.Set{Compute: client}
	})
}

// TestImportRetryOfAKeyPairWithoutANonceStillReplays covers key pairs
// imported before #279. Their compute request id is the token's alone and
// they carry no import nonce, so a retry under the token must still send
// that request id and body, and compute replays it.
func TestImportRetryOfAKeyPairWithoutANonceStillReplays(t *testing.T) {
	ctx := context.Background()
	client, world := dialKeyWorld(t)
	account := mustAccount(t)
	pair, err := sshkey.Generate(resource.KeyTypeEd25519, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "old-import-token", Fingerprint: "old-import-fp"}
	labels := nameLabels("laptop")
	labels[labelFingerprint] = m.Fingerprint
	id := derivedID("key-", account.String(), "key-name", "laptop")
	// The request an import made before #279 sent.
	if _, err := world.CreateKeyPair(ctx, &computev1.CreateKeyPairRequest{
		Parent: regionParent(project(account)), KeyPairId: id, RequestId: requestUUID(m.Key, "key"),
		KeyPair: &computev1.KeyPair{Labels: labels, Spec: &computev1.KeyPairSpec{PublicKey: pair.Public}},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := client.CreateKeyPair(ctx, m, resource.CreateKeyPairRequest{Name: "laptop", PublicKey: pair.Public})
	if err != nil || len(got.Items) != 1 || got.Items[0].ID.String() != id {
		t.Fatalf("retry of an import made before #279: want a replay, got %v %+v", err, got.Items)
	}
	if len(world.keys) != 1 || len(world.requests) != 1 {
		t.Fatalf("compute holds %d key pairs and %d requests, want 1 and 1", len(world.keys), len(world.requests))
	}
}
