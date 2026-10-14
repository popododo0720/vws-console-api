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

// rfc4716Key is a 2048-bit RSA key as ssh-keygen -e writes it.
const rfc4716Key = "---- BEGIN SSH2 PUBLIC KEY ----\n" +
	"Comment: \"2048-bit RSA, converted by me@laptop from OpenSSH\"\n" +
	"AAAAB3NzaC1yc2EAAAADAQABAAABAQClx+r6bOncI1UxjkWluLJh9YURn5VSLugTDfOBvM\n" +
	"6d1EjqWNRFSkQrLnf6EBSQJM0/+pEPXUtKyLynaeaK/T7RDuyurcZmo0ovWib/CTQz08Bm\n" +
	"lOs6brqv0TD/3eQmK2o6cSpVKXWKKalyFJwfK3t3i8ZZCuPw6+VWTVoNq+L71oIP/hJgF9\n" +
	"QJb3F863V+3yoly4RN3dXPADcBJVp/qPmA3AXuolprWOj7eYAAvaxqyiKUt/Htt4L55Gey\n" +
	"+5fR4fjnH/E2VA1FZotnqG6Bf6nfqfnxJ2IV6hZr6pfQV3psbbzt/tMjhOYBBgAr0R120I\n" +
	"Nm4MIQI8eY9Zgog8QWTIQN\n" +
	"---- END SSH2 PUBLIC KEY ----\n"

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
	if fp := edKey.Items[0].Fingerprint; len(fp) != 44 || !strings.HasSuffix(fp, "=") {
		t.Fatalf("ed25519 fingerprint: %+v", edKey.Items)
	}
	if len(rsaKey.Items[0].Fingerprint) != 59 || strings.Count(rsaKey.Items[0].Fingerprint, ":") != 19 {
		t.Fatalf("created rsa fingerprint is not EC2's colon SHA-1: %q", rsaKey.Items[0].Fingerprint)
	}
	ppk, err := set.Compute.CreateKeyPair(ctx, mut("ppk"), resource.CreateKeyPairRequest{Name: "ppk-key", Type: resource.KeyTypeEd25519, Format: resource.KeyFormatPPK})
	if err != nil || sshkey.VerifyPPK(ppk.Items[0].Material) != nil || !strings.Contains(ppk.Items[0].Material, "Comment: ppk-key\n") {
		t.Fatalf("ppk key: %v %+v", err, ppk.Items)
	}
	rfc, err := set.Compute.CreateKeyPair(ctx, mut("rfc4716"), resource.CreateKeyPairRequest{Name: "rfc4716", PublicKey: rfc4716Key})
	rfcWant, perr := sshkey.ParsePublic(rfc4716Key)
	if err != nil || perr != nil || rfc.Items[0].Fingerprint != rfcWant.AWSFingerprint || rfc.Items[0].Type != resource.KeyTypeRSA {
		t.Fatalf("rfc4716 import: %v %v %+v", err, perr, rfc.Items)
	}
	rfcListed, err := set.Compute.DescribeKeyPairs(ctx, scope, resource.KeyPairQuery{Names: []string{"rfc4716", "rsa-key"}, Page: resource.PageRequest{Size: 50}})
	if err != nil || len(rfcListed.Items) != 2 {
		t.Fatalf("describe rfc4716: %v %+v", err, rfcListed.Items)
	}
	for _, k := range rfcListed.Items {
		if (k.Name == "rfc4716" && k.Fingerprint != rfcWant.AWSFingerprint) || (k.Name == "rsa-key" && k.Fingerprint != rsaKey.Items[0].Fingerprint) {
			t.Fatalf("described fingerprint differs from create: %+v", k)
		}
	}
	want, err := sshkey.ParsePublic(importedKey)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := set.Compute.CreateKeyPair(ctx, mut("import"), resource.CreateKeyPairRequest{Name: "laptop", PublicKey: importedKey})
	if err != nil || imported.Items[0].Material != "" || imported.Items[0].Fingerprint != want.AWSFingerprint {
		t.Fatalf("import: %v %+v", err, imported.Items)
	}
	listed, err := set.Compute.DescribeKeyPairs(ctx, scope, resource.KeyPairQuery{Names: []string{"laptop"}, Page: resource.PageRequest{Size: 50}})
	if err != nil || len(listed.Items) != 1 || listed.Items[0].Fingerprint != want.AWSFingerprint || listed.Items[0].Type != resource.KeyTypeEd25519 {
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
