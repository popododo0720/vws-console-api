package backendtest

import (
	"context"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sshkey"
)

// importedKey is an ed25519 public key line a user would paste from
// ~/.ssh/id_ed25519.pub.
const importedKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG417cXtz5jVkH8Cu0D4exQ0iqZ8aXluTLeM0PhuoDH1 me@laptop"

// exerciseKeyLaunch covers #128: the private key formats CreateKeyPair returns,
// ImportKeyPair, and a launch that names a key pair and carries user data.
func exerciseKeyLaunch(ctx context.Context, t *testing.T, set backend.Set, account resource.AccountID, subnet resource.SubnetID, img resource.ImageID) {
	t.Helper()
	scope := backend.Scope{Account: account}
	mut := func(key string) backend.Mutation {
		return backend.Mutation{Scope: scope, Key: "k-" + key, Fingerprint: "fp-" + key}
	}
	rsaKey, err := set.Compute.CreateKeyPair(ctx, mut("rsa"), resource.CreateKeyPairRequest{Name: "rsa-key", Type: resource.KeyTypeRSA})
	if err != nil || !strings.HasPrefix(rsaKey.Items[0].Material, "-----BEGIN RSA PRIVATE KEY-----\n") || rsaKey.Items[0].Type != resource.KeyTypeRSA {
		t.Fatalf("rsa key: %v %+v", err, rsaKey.Items)
	}
	edKey, err := set.Compute.CreateKeyPair(ctx, mut("ed"), resource.CreateKeyPairRequest{Name: "ed-key", Type: resource.KeyTypeEd25519})
	if err != nil || !strings.HasPrefix(edKey.Items[0].Material, "-----BEGIN OPENSSH PRIVATE KEY-----\n") || edKey.Items[0].Type != resource.KeyTypeEd25519 {
		t.Fatalf("ed25519 key: %v %+v", err, edKey.Items)
	}
	want, err := sshkey.ParsePublic(importedKey)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := set.Compute.CreateKeyPair(ctx, mut("import"), resource.CreateKeyPairRequest{Name: "laptop", PublicKey: importedKey})
	if err != nil || imported.Items[0].Material != "" || imported.Items[0].Fingerprint != want.Fingerprint {
		t.Fatalf("import: %v %+v", err, imported.Items)
	}
	listed, err := set.Compute.DescribeKeyPairs(ctx, scope, resource.KeyPairQuery{Names: []string{"laptop"}, Page: resource.PageRequest{Size: 50}})
	if err != nil || len(listed.Items) != 1 || listed.Items[0].Fingerprint != want.Fingerprint || listed.Items[0].Type != resource.KeyTypeEd25519 {
		t.Fatalf("describe imported: %v %+v", err, listed.Items)
	}
	if _, err := set.Compute.RunInstances(ctx, mut("run-nokey"), resource.RunInstancesRequest{
		ImageID: img, InstanceType: "vws.small", SubnetID: subnet, Count: 1, KeyName: "nope",
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("unknown key: %v", err)
	}
	userData := "#cloud-config\nruncmd:\n  - echo hi > /tmp/vws-user-data\n"
	run, err := set.Compute.RunInstances(ctx, mut("run-key"), resource.RunInstancesRequest{
		ImageID: img, InstanceType: "vws.small", SubnetID: subnet, Count: 1, KeyName: "laptop", UserData: userData,
	})
	if err != nil || run.Items[0].KeyName != "laptop" {
		t.Fatalf("run with key: %v %+v", err, run.Items)
	}
	one, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{IDs: []resource.InstanceID{run.Items[0].ID}, Page: resource.PageRequest{Size: 50}})
	if err != nil || len(one.Items) != 1 || one.Items[0].KeyName != "laptop" || one.Items[0].UserData != userData {
		t.Fatalf("describe one: %v %+v", err, one.Items)
	}
	all, err := set.Compute.DescribeInstances(ctx, scope, resource.InstanceQuery{Page: resource.PageRequest{Size: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	for _, inst := range all.Items {
		if inst.ID == run.Items[0].ID && inst.KeyName == "laptop" {
			return
		}
	}
	t.Fatalf("list lost keyName: %+v", all.Items)
}
