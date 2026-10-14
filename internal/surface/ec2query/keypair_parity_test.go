package ec2query

import (
	"crypto/md5" //nolint:gosec // EC2's imported RSA fingerprint
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // EC2's created RSA fingerprint
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"html"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/sshkey"
)

func colonHex(sum []byte) string { return sshkey.ColonHex(hex.EncodeToString(sum)) }

func sshRSA(k *rsa.PublicKey) string {
	str := func(b []byte) []byte { return append(big.NewInt(int64(len(b))).FillBytes(make([]byte, 4)), b...) }
	n := k.N.Bytes()
	if n[0]&0x80 != 0 {
		n = append([]byte{0}, n...)
	}
	blob := append(append(str([]byte("ssh-rsa")), str(big.NewInt(int64(k.E)).Bytes())...), str(n)...)
	return "ssh-rsa " + base64.StdEncoding.EncodeToString(blob)
}

// #128 follow-ups: fingerprints, import formats, RSA sizes, ppk and
// MissingParameter, as EC2 has them.
func TestKeyPairAWSParity(t *testing.T) {
	h, cred, now := harness(t)
	send := func(f url.Values, want int) string {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		if res.Code != want {
			t.Fatalf("%s %s: %d %s", f.Get("Action"), f.Get("KeyName"), res.Code, res.Body)
		}
		return res.Body.String()
	}
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	imp := func(name, material string, want int) string {
		t.Helper()
		return send(url.Values{"Action": {"ImportKeyPair"}, "KeyName": {name}, "PublicKeyMaterial": {b64(material)}}, want)
	}

	// Created RSA: SHA-1 of the PKCS#8 DER private key.
	made := send(url.Values{"Action": {"CreateKeyPair"}, "KeyName": {"made-rsa"}}, http.StatusOK)
	block, _ := pem.Decode([]byte(html.UnescapeString(xmlText(t, made, "keyMaterial"))))
	if block == nil {
		t.Fatalf("created rsa material: %s", made)
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(priv)
	sum1 := sha1.Sum(pkcs8) //nolint:gosec // EC2's format
	if got := xmlText(t, made, "keyFingerprint"); got != colonHex(sum1[:]) {
		t.Fatalf("created rsa fingerprint %q want %q", got, colonHex(sum1[:]))
	}
	if got := xmlText(t, send(url.Values{"Action": {"DescribeKeyPairs"}, "KeyName.1": {"made-rsa"}}, http.StatusOK), "keyFingerprint"); got != colonHex(sum1[:]) {
		t.Fatalf("described created rsa %q", got)
	}

	// Imported ed25519: base64 SHA-256 of the blob.
	edBlob, _ := base64.StdEncoding.DecodeString(strings.Fields(laptopKey)[1])
	sum256 := sha256.Sum256(edBlob)
	if got := xmlText(t, imp("ed", laptopKey, http.StatusOK), "keyFingerprint"); got != base64.StdEncoding.EncodeToString(sum256[:]) {
		t.Fatalf("ed25519 fingerprint %q", got)
	}

	// Imported RSA in every format and size EC2 takes: MD5 of the PKIX DER.
	for _, bits := range []int{1024, 2048, 4096} {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		pkix, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		sum := md5.Sum(pkix) //nolint:gosec // EC2's format
		line := sshRSA(&k.PublicKey)
		formats := map[string]string{
			"openssh": line + " me@host",
			"rfc4716": "---- BEGIN SSH2 PUBLIC KEY ----\nComment: \"me@host\"\n" + strings.Fields(line)[1] + "\n---- END SSH2 PUBLIC KEY ----\n",
			"der":     string(pkix),
			"der-b64": base64.StdEncoding.EncodeToString(pkix),
		}
		for format, material := range formats {
			name := format + "-" + big.NewInt(int64(bits)).String()
			if got := xmlText(t, imp(name, material, http.StatusOK), "keyFingerprint"); got != colonHex(sum[:]) {
				t.Fatalf("%s fingerprint %q want %q", name, got, colonHex(sum[:]))
			}
		}
	}

	// ECDSA, DSA and RSA outside 1024..4096 are InvalidKey.Format.
	tooBig, _ := rand.Prime(rand.Reader, 4097)
	for name, material := range map[string]string{
		"ecdsa":   "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEm0",
		"rsa4097": sshRSA(&rsa.PublicKey{N: tooBig, E: 65537}),
	} {
		if got := imp(name, material, http.StatusBadRequest); !strings.Contains(got, "<Code>InvalidKey.Format</Code>") {
			t.Fatalf("%s: %s", name, got)
		}
	}

	// No PublicKeyMaterial is MissingParameter.
	if got := send(url.Values{"Action": {"ImportKeyPair"}, "KeyName": {"none"}}, http.StatusBadRequest); !strings.Contains(got, "<Code>MissingParameter</Code>") {
		t.Fatalf("missing material: %s", got)
	}

	// KeyFormat=ppk returns a PuTTY key; other formats are refused.
	for _, typ := range []string{"rsa", "ed25519"} {
		got := send(url.Values{"Action": {"CreateKeyPair"}, "KeyName": {"ppk-" + typ}, "KeyType": {typ}, "KeyFormat": {"ppk"}}, http.StatusOK)
		material := html.UnescapeString(xmlText(t, got, "keyMaterial"))
		if !strings.HasPrefix(material, "PuTTY-User-Key-File-2: ") || !strings.Contains(material, "Comment: ppk-"+typ+"\n") {
			t.Fatalf("ppk %s: %s", typ, material)
		}
		if err := sshkey.VerifyPPK(material); err != nil {
			t.Fatalf("ppk %s: %v", typ, err)
		}
	}
	send(url.Values{"Action": {"CreateKeyPair"}, "KeyName": {"jks"}, "KeyFormat": {"jks"}}, http.StatusBadRequest)
}
