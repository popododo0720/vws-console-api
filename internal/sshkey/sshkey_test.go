package sshkey

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func stream(seed string) *bytes.Reader {
	var buf []byte
	for i := 0; len(buf) < 1<<20; i++ {
		sum := sha256.Sum256([]byte(seed + string(rune(i))))
		buf = append(buf, sum[:]...)
	}
	return bytes.NewReader(buf)
}

func TestRSAIsPKCS1PEM(t *testing.T) {
	pair, err := Generate(resource.KeyTypeRSA, stream("rsa"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(pair.Private))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatalf("private key %q", pair.Private)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil || key.N.BitLen() != 2048 {
		t.Fatalf("pkcs1: %v", err)
	}
	if err := key.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !strings.HasPrefix(pair.Public, "ssh-rsa ") {
		t.Fatalf("public %q", pair.Public)
	}
	sshKeygenAgrees(t, pair)
}

func TestEd25519IsOpenSSH(t *testing.T) {
	pair, err := Generate(resource.KeyTypeEd25519, stream("ed"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pair.Private, "-----BEGIN OPENSSH PRIVATE KEY-----\n") || !strings.HasPrefix(pair.Public, "ssh-ed25519 ") {
		t.Fatalf("%q %q", pair.Private, pair.Public)
	}
	sshKeygenAgrees(t, pair)
}

func TestEd25519GenerateIsDeterministic(t *testing.T) {
	a, err := Generate(resource.KeyTypeEd25519, stream("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(resource.KeyTypeEd25519, stream("same"))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("ed25519 differs")
	}
}

// crypto/rsa ignores the reader it is given, so an RSA key cannot be fixed by
// a stream. The same stream must give unrelated keys.
func TestRSAKeyIsNotAFunctionOfTheReader(t *testing.T) {
	a, err := Generate(resource.KeyTypeRSA, stream("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(resource.KeyTypeRSA, stream("same"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("the same stream gave the same RSA key")
	}
}

// sshKeygenAgrees asks OpenSSH to load the private key and print its public
// half. That is what ssh -i does with the file a user saves.
func sshKeygenAgrees(t *testing.T, pair Pair) {
	t.Helper()
	bin, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	path := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(path, []byte(pair.Private), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), bin, "-y", "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	if got := strings.Fields(string(out)); len(got) < 2 || got[0]+" "+got[1] != pair.Public {
		t.Fatalf("ssh-keygen public %q, want %q", out, pair.Public)
	}
}

func TestParsePublic(t *testing.T) {
	pair, err := Generate(resource.KeyTypeEd25519, stream("p"))
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{pair.Public, pair.Public + " me@host\n", "  " + pair.Public + "\r\n"} {
		got, err := ParsePublic(in)
		if err != nil || !strings.HasPrefix(got.Line, pair.Public) || got.Type != resource.KeyTypeEd25519 {
			t.Fatalf("%q: %+v %v", in, got, err)
		}
	}
	rsa, err := Generate(resource.KeyTypeRSA, stream("p"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParsePublic(rsa.Public); err != nil || got.Type != resource.KeyTypeRSA {
		t.Fatalf("rsa: %+v %v", got, err)
	}
	blob := strings.Fields(pair.Public)[1]
	for _, bad := range []string{"", "ssh-ed25519", "ssh-ed25519 !!!", "ssh-dss " + blob, "ssh-rsa " + blob, pair.Public + "\n" + pair.Public} {
		if _, err := ParsePublic(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestFingerprintIsHexSHA256OfBlob(t *testing.T) {
	pair, err := Generate(resource.KeyTypeEd25519, stream("f"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePublic(pair.Public)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Fingerprint) != 64 || got.Fingerprint != pair.Fingerprint {
		t.Fatalf("%q %q", got.Fingerprint, pair.Fingerprint)
	}
}
