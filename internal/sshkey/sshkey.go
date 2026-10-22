// Package sshkey makes and reads the SSH keys behind EC2 key pairs.
//
// CreateKeyPair returns the private key the way AWS does: an RSA key as a
// PKCS#1 PEM block, an ed25519 key in the OpenSSH private key format. The
// compute service stores only the OpenSSH public key line.
package sshkey

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

const rsaBits = 2048

// Pair is a generated key. Public is "algorithm base64" with no comment.
// Fingerprint is the lowercase hex SHA-256 of the public key blob, the value
// the compute service stores.
// AWSFingerprint is the fingerprint EC2 reports for a key it created: for
// RSA the SHA-1 of the PKCS#8 DER private key, for ed25519 the base64 SHA-256
// of the public key blob.
type Pair struct {
	Private        string
	Public         string
	Fingerprint    string
	AWSFingerprint string

	algo, blob, ppkPrivate string
}

// Public is a parsed authorized_keys line.
type Public struct {
	Type        resource.KeyType
	Line        string
	Fingerprint string
	// AWSFingerprint is what EC2 reports for an imported key: for RSA the MD5
	// of the DER SubjectPublicKeyInfo, for ed25519 the base64 SHA-256 of the
	// public key blob.
	AWSFingerprint string
}

// Generate makes a key of typ from r. The key is a function of r alone, so a
// caller that serves a user passes crypto/rand.Reader. Tests pass a fixed
// stream to get a fixed key.
func Generate(typ resource.KeyType, r io.Reader) (Pair, error) {
	switch typ {
	case resource.KeyTypeRSA:
		return generateRSA(r)
	case resource.KeyTypeEd25519:
		return generateEd25519(r)
	default:
		return Pair{}, fmt.Errorf("key type %q", typ)
	}
}

func generateRSA(r io.Reader) (Pair, error) {
	// crypto/rsa ignores its reader since Go 1.26, so the primes are drawn here
	// from r. That keeps test keys fixed under a fixed stream.
	e := big.NewInt(65537)
	one := big.NewInt(1)
	for {
		p, err := prime(r, rsaBits/2)
		if err != nil {
			return Pair{}, err
		}
		q, err := prime(r, rsaBits/2)
		if err != nil {
			return Pair{}, err
		}
		if p.Cmp(q) == 0 {
			continue
		}
		phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
		d := new(big.Int).ModInverse(e, phi)
		if d == nil {
			continue
		}
		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: int(e.Int64())},
			D:         d,
			Primes:    []*big.Int{p, q},
		}
		if key.N.BitLen() != rsaBits {
			continue
		}
		key.Precompute()
		if err := key.Validate(); err != nil {
			return Pair{}, fmt.Errorf("rsa key: %w", err)
		}
		blob := sshString("ssh-rsa") + sshString(string(mpint(e))) + sshString(string(mpint(key.N)))
		private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		out := pair(string(private), "ssh-rsa", blob)
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return Pair{}, fmt.Errorf("rsa pkcs8: %w", err)
		}
		out.AWSFingerprint = ColonHex(sha1Hex(pkcs8))
		iqmp := new(big.Int).ModInverse(q, p)
		out.ppkPrivate = sshString(string(mpint(d))) + sshString(string(mpint(key.Primes[0]))) +
			sshString(string(mpint(key.Primes[1]))) + sshString(string(mpint(iqmp)))
		return out, nil
	}
}

// prime returns a bits-long prime with the top two bits set, so the product
// of two of them is exactly twice as long.
func prime(r io.Reader, bits int) (*big.Int, error) {
	buf := make([]byte, bits/8)
	for {
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("read prime candidate: %w", err)
		}
		buf[0] |= 0xc0
		buf[len(buf)-1] |= 1
		p := new(big.Int).SetBytes(buf)
		if p.ProbablyPrime(20) {
			return p, nil
		}
	}
}

func generateEd25519(r io.Reader) (Pair, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		return Pair{}, fmt.Errorf("read ed25519 seed: %w", err)
	}
	var check [4]byte
	if _, err := io.ReadFull(r, check[:]); err != nil {
		return Pair{}, fmt.Errorf("read check bytes: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return Pair{}, errors.New("ed25519 public key")
	}
	blob := sshString("ssh-ed25519") + sshString(string(pub))
	// openssh-key-v1, unencrypted: PROTOCOL.key in the OpenSSH source.
	secret := string(check[:]) + string(check[:]) + blob + sshString(string(priv)) + sshString("")
	for i := byte(1); len(secret)%8 != 0; i++ {
		secret += string([]byte{i})
	}
	body := "openssh-key-v1\x00" + sshString("none") + sshString("none") + sshString("") +
		string(binary.BigEndian.AppendUint32(nil, 1)) + sshString(blob) + sshString(secret)
	private := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte(body)})
	p := pair(string(wrap70(private)), "ssh-ed25519", blob)
	p.AWSFingerprint = base64SHA256(blob)
	p.ppkPrivate = sshString(string(seed))
	return p, nil
}

// wrap70 rewraps the base64 body at 70 columns, as ssh-keygen writes it.
func wrap70(block []byte) []byte {
	lines := strings.Split(strings.TrimSpace(string(block)), "\n")
	b64 := strings.Join(lines[1:len(lines)-1], "")
	var out strings.Builder
	out.WriteString(lines[0] + "\n")
	for len(b64) > 70 {
		out.WriteString(b64[:70] + "\n")
		b64 = b64[70:]
	}
	out.WriteString(b64 + "\n" + lines[len(lines)-1] + "\n")
	return []byte(out.String())
}

func pair(private, algo, blob string) Pair {
	sum := sha256.Sum256([]byte(blob))
	return Pair{
		Private:     private,
		Public:      algo + " " + base64.StdEncoding.EncodeToString([]byte(blob)),
		Fingerprint: hex.EncodeToString(sum[:]),
		algo:        algo,
		blob:        blob,
	}
}

func sshString(s string) string {
	return string(binary.BigEndian.AppendUint32(nil, uint32(len(s)))) + s //nolint:gosec // SSH strings here are far below 4 GiB
}

func mpint(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		return append([]byte{0}, b...)
	}
	return b
}
