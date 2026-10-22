package backendtest

import (
	"context"
	"errors"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sshkey"
)

// KeyTokenMix is the #281 contract, one table for the fake and the gRPC
// client: a generated CreateKeyPair and an ImportKeyPair under the same
// client token keep separate records. A create never replays and never
// overwrites the record an import replays from, so an import retry under
// the token replays while the key pair it made lives, whatever creates ran
// under the token in between. A create is still judged by the name alone.
//
// It needs only the key pair methods of set.Compute, so a compute stub that
// models key pair ids and request ids can run it.
func KeyTokenMix(t *testing.T, newSet Harness) {
	t.Helper()
	ctx := context.Background()
	set := newSet()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account}
	ed, err := sshkey.ParsePublic(importedKey)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]resource.KeyPairID{}
	importReq := func(name string) resource.CreateKeyPairRequest {
		return resource.CreateKeyPairRequest{Name: name, PublicKey: importedKey}
	}
	createReq := func(name string) resource.CreateKeyPairRequest {
		return resource.CreateKeyPairRequest{Name: name, Type: resource.KeyTypeEd25519}
	}
	// The kernel fingerprints the normalized request, so an import and a
	// create of another name under one token differ in fingerprint only.
	mut := func(token, name string, req resource.CreateKeyPairRequest) backend.Mutation {
		kind := "create"
		if req.PublicKey != "" {
			kind = "import"
		}
		return backend.Mutation{Scope: scope, Key: token, Fingerprint: "fp-" + kind + "-" + name}
	}
	live := func(label, name string, want resource.KeyPairID, fingerprint string) {
		t.Helper()
		listed, err := set.Compute.DescribeKeyPairs(ctx, scope,
			resource.KeyPairQuery{Names: []string{name}, Page: resource.PageRequest{Size: 50}})
		if err != nil || len(listed.Items) != 1 || listed.Items[0].ID != want ||
			(fingerprint != "" && listed.Items[0].Fingerprint != fingerprint) {
			t.Fatalf("key token mix, %s: %s is not live as %s: %v %+v", label, name, want, err, listed.Items)
		}
	}
	imported := func(label, token, name string, replay bool) {
		t.Helper()
		req := importReq(name)
		got, err := set.Compute.CreateKeyPair(ctx, mut(token, name, req), req)
		if err != nil || len(got.Items) != 1 || got.Items[0].Material != "" || got.Items[0].Fingerprint != ed.AWSFingerprint {
			t.Fatalf("key token mix, %s: want an imported key pair, got %v %+v", label, err, got.Items)
		}
		if replay && got.Items[0].ID != ids[name] {
			t.Fatalf("key token mix, %s: want a replay of %s, got %s", label, ids[name], got.Items[0].ID)
		}
		ids[name] = got.Items[0].ID
		live(label, name, ids[name], ed.AWSFingerprint)
	}
	created := func(label, token, name string) {
		t.Helper()
		req := createReq(name)
		got, err := set.Compute.CreateKeyPair(ctx, mut(token, name, req), req)
		if err != nil || len(got.Items) != 1 || got.Items[0].Material == "" {
			t.Fatalf("key token mix, %s: want a new key pair with its private key, got %v %+v", label, err, got.Items)
		}
		ids[name] = got.Items[0].ID
		live(label, name, ids[name], "")
	}
	duplicate := func(label, token, name string, req resource.CreateKeyPairRequest) {
		t.Helper()
		got, err := set.Compute.CreateKeyPair(ctx, mut(token, name, req), req)
		var re *resource.Error
		dup := errors.As(err, &re) && re.Code == resource.CodeAlreadyExists && re.Kind == resource.KindKeyPair
		if !dup || len(got.Items) != 0 {
			t.Fatalf("key token mix, %s: want AlreadyExists of KindKeyPair and no items, got %v %+v", label, err, got.Items)
		}
	}
	deleted := func(label, name string) {
		t.Helper()
		m := backend.Mutation{Scope: scope, Key: "k-mix-delete-" + label, Fingerprint: "fp-mix-delete-" + label}
		if _, err := set.Compute.DeleteKeyPair(ctx, m, resource.DeleteKeyPairRequest{Name: name}); err != nil {
			t.Fatalf("key token mix, delete %s: %v", label, err)
		}
	}

	// Import, then a create of another name under the token, then the
	// import retry: the create must not take the import's record.
	imported("import a", "k-mix-1", "mix-a", false)
	created("create b under the import's token", "k-mix-1", "mix-b")
	imported("import a retried after the create", "k-mix-1", "mix-a", true)
	duplicate("create b retried", "k-mix-1", "mix-b", createReq("mix-b"))
	live("create b retried", "mix-b", ids["mix-b"], "")
	deleted("b", "mix-b")
	imported("import a retried after b is deleted", "k-mix-1", "mix-a", true)

	// Create first, then an import of another name under the token.
	created("create c", "k-mix-2", "mix-c")
	imported("import d under the create's token", "k-mix-2", "mix-d", false)
	imported("import d retried", "k-mix-2", "mix-d", true)
	duplicate("create c retried", "k-mix-2", "mix-c", createReq("mix-c"))

	// A create of the import's own name is a second key pair of that name.
	imported("import e", "k-mix-3", "mix-e", false)
	duplicate("create e under the import's token", "k-mix-3", "mix-e", createReq("mix-e"))
	imported("import e retried after the refused create", "k-mix-3", "mix-e", true)

	// Once a create holds the name the import made, the import retry is a
	// second key pair of that name.
	imported("import f", "k-mix-4", "mix-f", false)
	deleted("f", "mix-f")
	created("create f under the import's token", "k-mix-4", "mix-f")
	duplicate("import f retried while the created f lives", "k-mix-4", "mix-f", importReq("mix-f"))
	live("import f retried while the created f lives", "mix-f", ids["mix-f"], "")
}
