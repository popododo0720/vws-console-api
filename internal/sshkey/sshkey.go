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
type Pair struct {
	Private     string
	Public      string
	Fingerprint string
}

// Public is a parsed authorized_keys line.
type Public struct {
	Type        resource.KeyType
	Line        string
	Fingerprint string
}

// Generate makes a key of typ from r. The same bytes from r give the same key,
// so a retried CreateKeyPair returns the private key it returned the first time.
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
	// to keep the key a function of r.
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
		return pair(string(private), "ssh-rsa", blob), nil
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
	return pair(string(wrap70(private)), "ssh-ed25519", blob), nil
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
	}
}

// ParsePublic reads one authorized_keys line of an RSA or ed25519 key. It
// keeps an optional comment and drops surrounding whitespace.
func ParsePublic(line string) (Public, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.ContainsAny(line, "\r\n") {
		return Public{}, errors.New("want one OpenSSH public key line")
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Public{}, errors.New("want an algorithm and a base64 key")
	}
	var typ resource.KeyType
	switch fields[0] {
	case "ssh-rsa":
		typ = resource.KeyTypeRSA
	case "ssh-ed25519":
		typ = resource.KeyTypeEd25519
	default:
		return Public{}, fmt.Errorf("key algorithm %q is not ssh-rsa or ssh-ed25519", fields[0])
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(blob) < 4 {
		return Public{}, errors.New("key is not base64")
	}
	n := binary.BigEndian.Uint32(blob)
	if uint64(n) > uint64(len(blob)-4) || string(blob[4:4+n]) != fields[0] {
		return Public{}, errors.New("key blob does not match its algorithm")
	}
	sum := sha256.Sum256(blob)
	return Public{Type: typ, Line: strings.Join(fields, " "), Fingerprint: hex.EncodeToString(sum[:])}, nil
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
