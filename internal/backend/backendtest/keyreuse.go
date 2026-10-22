package backendtest

import (
	"context"
	"errors"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// exerciseKeyTokenReuse covers #268. EC2 CreateKeyPair takes no client
// token, so a create under a used token is judged by the name alone. While
// the name lives it is InvalidKeyPair.Duplicate with no private key. Once the
// name is free, after a delete or for another name, it creates a new key pair
// with a new, unrelated private key. The fake and the gRPC client run this
// one table.
func exerciseKeyTokenReuse(ctx context.Context, t *testing.T, set backend.Set, scope backend.Scope) {
	t.Helper()
	const token = "k-token-reuse"
	ed := resource.KeyTypeEd25519
	create := func(name string) func() (resource.Accepted[resource.KeyPair], error) {
		return func() (resource.Accepted[resource.KeyPair], error) {
			m := backend.Mutation{Scope: scope, Key: token, Fingerprint: "fp-token-reuse-" + name}
			return set.Compute.CreateKeyPair(ctx, m, resource.CreateKeyPairRequest{Name: name, Type: ed})
		}
	}
	remove := func(name string) func() (resource.Accepted[resource.KeyPair], error) {
		return func() (resource.Accepted[resource.KeyPair], error) {
			m := backend.Mutation{Scope: scope, Key: "k-token-reuse-delete-" + name, Fingerprint: "fp-delete-" + name}
			return set.Compute.DeleteKeyPair(ctx, m, resource.DeleteKeyPairRequest{Name: name})
		}
	}
	seen := map[string]bool{}
	for _, step := range []struct {
		label  string
		call   func() (resource.Accepted[resource.KeyPair], error)
		newKey bool
	}{
		{"first create", create("reuse-a"), true},
		{"retry while the name lives", create("reuse-a"), false},
		{"delete", remove("reuse-a"), false},
		{"same token after the delete", create("reuse-a"), true},
		{"retry of the new key pair", create("reuse-a"), false},
		{"same token, another free name", create("reuse-b"), true},
		{"retry of the other name", create("reuse-b"), false},
	} {
		got, err := step.call()
		switch {
		case step.label == "delete":
			if err != nil {
				t.Fatalf("token reuse, %s: %v", step.label, err)
			}
		case step.newKey:
			if err != nil || len(got.Items) != 1 || got.Items[0].Material == "" {
				t.Fatalf("token reuse, %s: want a new key pair with a private key, got %v %+v", step.label, err, got.Items)
			}
			key := got.Items[0]
			if seen[key.Material] || seen[key.Fingerprint] {
				t.Fatalf("token reuse, %s: the private key or fingerprint repeats an earlier one", step.label)
			}
			seen[key.Material], seen[key.Fingerprint] = true, true
		default:
			var re *resource.Error
			duplicate := errors.As(err, &re) && re.Code == resource.CodeAlreadyExists && re.Kind == resource.KindKeyPair
			if !duplicate || len(got.Items) != 0 {
				t.Fatalf("token reuse, %s: want AlreadyExists of KindKeyPair and no items, got %v, %d items",
					step.label, err, len(got.Items))
			}
		}
	}
	q := resource.KeyPairQuery{Names: []string{"reuse-a", "reuse-b"}, Page: resource.PageRequest{Size: 50}}
	listed, err := set.Compute.DescribeKeyPairs(ctx, scope, q)
	if err != nil || len(listed.Items) != 2 {
		t.Fatalf("token reuse: want reuse-a and reuse-b listed once each, got %v %+v", err, listed.Items)
	}
}
