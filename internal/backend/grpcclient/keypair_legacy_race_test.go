package grpcclient

import (
	"context"
	"crypto/rand"
	"sync/atomic"
	"testing"

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sshkey"
)

// TestLegacyDeleteBetweenLookupAndCreateKeepsOneKeyPair is #278. A key pair
// made before #273 has an id derived from its client token, so compute's
// claim on the name-derived id cannot see it. Create A looks the name up and
// sees the legacy key pair. Before A creates, the legacy key pair is deleted
// and create B, which finds the name free, succeeds. Then A goes on. Exactly
// one of A and B may hold the name; the other is InvalidKeyPair.Duplicate.
func TestLegacyDeleteBetweenLookupAndCreateKeepsOneKeyPair(t *testing.T) {
	ctx := context.Background()
	client, world := dialKeyWorld(t)
	account := mustAccount(t)
	scope := backend.Scope{Account: account}
	pair, err := sshkey.Generate(resource.KeyTypeEd25519, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	legacyID := derivedID("key-", "old-mutation-key", "key")
	legacyName := keyPairName(project(account), legacyID)
	world.keys[legacyName] = &computev1.KeyPair{
		Name: legacyName, Labels: nameLabels("legacy"), Spec: &computev1.KeyPairSpec{PublicKey: pair.Public},
	}

	// Pause create A right after its name lookup has seen the legacy key pair.
	looked, resume := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	world.afterList = func() {
		if first.CompareAndSwap(false, true) {
			close(looked)
			<-resume
		}
	}
	req := resource.CreateKeyPairRequest{Name: "legacy", Type: resource.KeyTypeEd25519}
	type result struct {
		got resource.Accepted[resource.KeyPair]
		err error
	}
	done := make(chan result, 1)
	go func() {
		m := backend.Mutation{Scope: scope, Key: "token-a", Fingerprint: "fp-a"}
		got, err := client.CreateKeyPair(ctx, m, req)
		done <- result{got, err}
	}()
	<-looked

	del := backend.Mutation{Scope: scope, Key: "token-delete", Fingerprint: "fp-delete"}
	if _, err := client.DeleteKeyPair(ctx, del, resource.DeleteKeyPairRequest{Name: "legacy"}); err != nil {
		t.Fatalf("delete the legacy key pair: %v", err)
	}
	b, errB := client.CreateKeyPair(ctx, backend.Mutation{Scope: scope, Key: "token-b", Fingerprint: "fp-b"}, req)
	close(resume)
	a := <-done

	won := 0
	for _, r := range []result{a, {b, errB}} {
		if r.err == nil {
			won++
			continue
		}
		requireDuplicate(t, "losing create", r.got, r.err)
	}
	named := 0
	for _, kp := range world.keys {
		if labelName(kp.GetLabels()) == "legacy" {
			named++
		}
	}
	if won != 1 || named != 1 {
		t.Fatalf("%d creates succeeded and compute holds %d key pairs named legacy, want 1 and 1 (A: %v, B: %v)",
			won, named, a.err, errB)
	}
}

// TestImportRetryUnderTheTokenStillReplays guards #278's change to the
// create target. An import retried under its token with the same key is the
// same compute request at the same name-derived id, so compute replays it.
func TestImportRetryUnderTheTokenStillReplays(t *testing.T) {
	ctx := context.Background()
	client, world := dialKeyWorld(t)
	pair, err := sshkey.Generate(resource.KeyTypeEd25519, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := backend.Mutation{Scope: backend.Scope{Account: mustAccount(t)}, Key: "import-token", Fingerprint: "import-fp"}
	req := resource.CreateKeyPairRequest{Name: "laptop", PublicKey: pair.Public}
	first, err := client.CreateKeyPair(ctx, m, req)
	if err != nil || len(first.Items) != 1 {
		t.Fatalf("import: %v %+v", err, first.Items)
	}
	again, err := client.CreateKeyPair(ctx, m, req)
	if err != nil || len(again.Items) != 1 || again.Items[0].ID != first.Items[0].ID || again.Items[0].Material != "" {
		t.Fatalf("import retry: want the same key pair replayed, got %v %+v", err, again.Items)
	}
	if len(world.keys) != 1 {
		t.Fatalf("compute holds %d key pairs, want 1", len(world.keys))
	}
}
