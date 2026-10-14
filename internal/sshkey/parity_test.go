package sshkey

import (
	"crypto/ed25519"
	"crypto/md5" //nolint:gosec // AWS fingerprints imported RSA keys with MD5
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // AWS fingerprints created RSA keys with SHA-1
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func colons(sum []byte) string {
	h := hex.EncodeToString(sum)
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// AWS: created RSA = SHA-1 of the PKCS#8 DER private key, with colons.
func TestCreatedRSAFingerprintIsSHA1OfPKCS8(t *testing.T) {
	pair, err := Generate(resource.KeyTypeRSA, stream("fp-rsa"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(pair.Private))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum(der) //nolint:gosec // AWS format
	if pair.AWSFingerprint != colons(sum[:]) {
		t.Fatalf("got %q want %q", pair.AWSFingerprint, colons(sum[:]))
	}
}

// AWS: ed25519 (created or imported) = base64 SHA-256 of the key blob, padded.
func TestEd25519FingerprintIsBase64SHA256(t *testing.T) {
	pair, err := Generate(resource.KeyTypeEd25519, stream("fp-ed"))
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := base64.StdEncoding.DecodeString(strings.Fields(pair.Public)[1])
	sum := sha256.Sum256(blob)
	want := base64.StdEncoding.EncodeToString(sum[:])
	pub, err := ParsePublic(pair.Public)
	if err != nil {
		t.Fatal(err)
	}
	if pair.AWSFingerprint != want || pub.AWSFingerprint != want {
		t.Fatalf("created %q imported %q want %q", pair.AWSFingerprint, pub.AWSFingerprint, want)
	}
}

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sshRSALine(k *rsa.PublicKey) string {
	blob := sshString("ssh-rsa") + sshString(string(mpint(bigE(k)))) + sshString(string(mpint(k.N)))
	return "ssh-rsa " + base64.StdEncoding.EncodeToString([]byte(blob))
}

// AWS: imported RSA = MD5 of the DER SubjectPublicKeyInfo, with colons, and
// every import format gives the same key.
func TestImportFormats(t *testing.T) {
	k := rsaKey(t, 2048)
	pkix, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum(pkix) //nolint:gosec // AWS format
	want := colons(sum[:])
	line := sshRSALine(&k.PublicKey)
	blob := strings.Fields(line)[1]
	var wrapped strings.Builder
	for b := blob; len(b) > 0; {
		n := min(70, len(b))
		wrapped.WriteString(b[:n] + "\n")
		b = b[n:]
	}
	inputs := map[string]string{
		"openssh":       line + " me@host\n",
		"rfc4716":       "---- BEGIN SSH2 PUBLIC KEY ----\nComment: \"2048-bit RSA, converted by me@host\\\n from OpenSSH\"\n" + wrapped.String() + "---- END SSH2 PUBLIC KEY ----\n",
		"der-pkix-b64":  base64.StdEncoding.EncodeToString(pkix),
		"der-pkcs1-b64": base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&k.PublicKey)),
		"der-raw":       string(pkix),
		"pem":           string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix})),
	}
	for name, in := range inputs {
		got, err := ParsePublic(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.Line != line && !strings.HasPrefix(got.Line, line+" ") {
			t.Fatalf("%s line %q", name, got.Line)
		}
		if got.AWSFingerprint != want || got.Type != resource.KeyTypeRSA {
			t.Fatalf("%s: %+v want %s", name, got, want)
		}
	}
}

func TestRSASizes(t *testing.T) {
	for _, bits := range []int{1024, 3072, 4096} {
		if _, err := ParsePublic(sshRSALine(&rsaKey(t, bits).PublicKey)); err != nil {
			t.Fatalf("%d bits: %v", bits, err)
		}
	}
	for _, bits := range []int{1023, 4097} {
		n, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParsePublic(sshRSALine(&rsa.PublicKey{N: n, E: 65537})); err == nil {
			t.Fatalf("%d bits accepted", bits)
		}
	}
}

func TestECDSAAndDSAAreRejected(t *testing.T) {
	for _, alg := range []string{"ecdsa-sha2-nistp256", "ssh-dss"} {
		line := alg + " " + base64.StdEncoding.EncodeToString([]byte(sshString(alg)+sshString("x")))
		if _, err := ParsePublic(line); err == nil {
			t.Fatalf("%s accepted", alg)
		}
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ParsePublic(base64.StdEncoding.EncodeToString(mustPKIX(t, pub))); err == nil {
		t.Fatal("DER ed25519 accepted; AWS takes DER for RSA only")
	}
}

func mustPKIX(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// PPK v2, as EC2 returns for KeyFormat=ppk.
func TestPPK(t *testing.T) {
	for _, typ := range []resource.KeyType{resource.KeyTypeRSA, resource.KeyTypeEd25519} {
		pair, err := Generate(typ, stream("ppk-"+string(typ)))
		if err != nil {
			t.Fatal(err)
		}
		ppk := pair.PPK("my key")
		alg := strings.Fields(pair.Public)[0]
		for _, want := range []string{
			"PuTTY-User-Key-File-2: " + alg + "\n", "Encryption: none\n", "Comment: my key\n",
			"Public-Lines: ", "Private-Lines: ", "Private-MAC: ",
		} {
			if !strings.Contains(ppk, want) {
				t.Fatalf("%s: no %q in\n%s", typ, want, ppk)
			}
		}
		if err := VerifyPPK(ppk); err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
	}
}

func bigE(k *rsa.PublicKey) *big.Int { return big.NewInt(int64(k.E)) }
