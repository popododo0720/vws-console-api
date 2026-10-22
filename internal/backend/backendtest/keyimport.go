package backendtest

import (
	"context"
	"errors"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sshkey"
)

// KeyImport is the ImportKeyPair contract of #279, one table for the fake
// and the gRPC client. EC2 ImportKeyPair takes no client token: a free name
// is imported, a live name is InvalidKeyPair.Duplicate. A retry of the same
// request under the same token while the key pair it made still lives is
// replayed, so an in-flight retry never makes a second key pair. Once that
// key pair is deleted, the same token and key import it again.
//
// It needs only the key pair methods of set.Compute, so a compute stub that
// models key pair ids and request ids can run it.
func KeyImport(t *testing.T, newSet Harness) {
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
	rsa, err := sshkey.ParsePublic(rfc4716Key)
	if err != nil {
		t.Fatal(err)
	}
	const name = "import-reuse"
	edReq := resource.CreateKeyPairRequest{Name: name, PublicKey: importedKey}
	rsaReq := resource.CreateKeyPairRequest{Name: name, PublicKey: rfc4716Key}
	mut := func(token, fingerprint string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: token, Fingerprint: fingerprint}
	}
	same, other := mut("k-import", "fp-import-ed"), mut("k-import-other", "fp-import-ed")
	reshaped := mut("k-import", "fp-import-rsa")

	var live resource.KeyPairID
	imported := func(label string, m backend.Mutation, req resource.CreateKeyPairRequest, want string, replay bool) {
		t.Helper()
		got, err := set.Compute.CreateKeyPair(ctx, m, req)
		if err != nil || len(got.Items) != 1 || got.Items[0].Material != "" || got.Items[0].Fingerprint != want {
			t.Fatalf("key import, %s: want an imported key pair, got %v %+v", label, err, got.Items)
		}
		if replay && got.Items[0].ID != live {
			t.Fatalf("key import, %s: replay returned %s, want %s", label, got.Items[0].ID, live)
		}
		live = got.Items[0].ID
		listed, err := set.Compute.DescribeKeyPairs(ctx, scope,
			resource.KeyPairQuery{Names: []string{name}, Page: resource.PageRequest{Size: 50}})
		if err != nil || len(listed.Items) != 1 || listed.Items[0].ID != live || listed.Items[0].Fingerprint != want {
			t.Fatalf("key import, %s: the key pair is not live: %v %+v", label, err, listed.Items)
		}
	}
	duplicate := func(label string, m backend.Mutation, req resource.CreateKeyPairRequest) {
		t.Helper()
		got, err := set.Compute.CreateKeyPair(ctx, m, req)
		var re *resource.Error
		dup := errors.As(err, &re) && re.Code == resource.CodeAlreadyExists && re.Kind == resource.KindKeyPair
		if !dup || len(got.Items) != 0 {
			t.Fatalf("key import, %s: want AlreadyExists of KindKeyPair and no items, got %v %+v", label, err, got.Items)
		}
	}
	deleted := func(label string) {
		t.Helper()
		m := mut("k-import-delete-"+label, "fp-import-delete-"+label)
		if _, err := set.Compute.DeleteKeyPair(ctx, m, resource.DeleteKeyPairRequest{Name: name}); err != nil {
			t.Fatalf("key import, delete %s: %v", label, err)
		}
	}

	imported("first import", same, edReq, ed.AWSFingerprint, false)
	imported("retry while live", same, edReq, ed.AWSFingerprint, true)
	duplicate("another token while live", other, edReq)
	deleted("first")
	imported("same token and key after the delete", same, edReq, ed.AWSFingerprint, false)
	imported("retry of the new key pair", same, edReq, ed.AWSFingerprint, true)
	duplicate("same token, another key while live", reshaped, rsaReq)
	deleted("second")
	imported("same token, another key after the delete", reshaped, rsaReq, rsa.AWSFingerprint, false)
	duplicate("same token, first key while the other lives", same, edReq)
}
