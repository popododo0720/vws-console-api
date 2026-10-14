package sshkey

import (
	"crypto/md5" //nolint:gosec // EC2 fingerprints imported RSA keys with MD5
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // EC2 fingerprints created RSA keys with SHA-1
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// RSA key sizes EC2 imports.
const (
	minImportBits = 1024
	maxImportBits = 4096
)

const (
	rfc4716Begin = "---- BEGIN SSH2 PUBLIC KEY ----"
	rfc4716End   = "---- END SSH2 PUBLIC KEY ----"
)

// ParsePublic reads key material in a format ImportKeyPair accepts: an
// OpenSSH line (RSA or ed25519), or for RSA only an RFC 4716 block or a DER
// key (SubjectPublicKeyInfo or PKCS#1; raw, base64 or PEM). Line is always
// the OpenSSH form; an OpenSSH comment is kept.
func ParsePublic(material string) (Public, error) {
	text := strings.TrimSpace(material)
	switch {
	case text == "":
		return Public{}, errors.New("key material is empty")
	case strings.HasPrefix(text, rfc4716Begin):
		blob, err := parseRFC4716(text)
		if err != nil {
			return Public{}, err
		}
		pub, err := fromBlob(blob, "")
		if err != nil {
			return Public{}, err
		}
		if pub.Type != resource.KeyTypeRSA {
			return Public{}, errors.New("RFC 4716 keys must be RSA")
		}
		return pub, nil
	case strings.HasPrefix(text, "ssh-") || strings.HasPrefix(text, "ecdsa-"):
		return parseOpenSSH(text)
	case strings.HasPrefix(text, "-----BEGIN"):
		block, rest := pem.Decode([]byte(text))
		if block == nil || len(strings.TrimSpace(string(rest))) > 0 {
			return Public{}, errors.New("want one PEM block")
		}
		return fromDER(block.Bytes)
	}
	if der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), "")); err == nil {
		return fromDER(der)
	}
	return fromDER([]byte(material))
}

func parseOpenSSH(line string) (Public, error) {
	if strings.ContainsAny(line, "\r\n") {
		return Public{}, errors.New("want one OpenSSH public key line")
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Public{}, errors.New("want an algorithm and a base64 key")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return Public{}, errors.New("key is not base64")
	}
	pub, err := fromBlob(blob, strings.Join(fields[2:], " "))
	if err != nil {
		return Public{}, err
	}
	if !strings.HasPrefix(pub.Line, fields[0]+" ") {
		return Public{}, errors.New("key blob does not match its algorithm")
	}
	return pub, nil
}

// fromBlob checks an SSH public key blob and builds the Public for it.
func fromBlob(blob []byte, comment string) (Public, error) {
	r := reader{b: blob}
	algo := r.str()
	var pub Public
	switch string(algo) {
	case "ssh-rsa":
		e, n := r.str(), r.str()
		if r.err || len(r.b) > 0 {
			return Public{}, errors.New("malformed ssh-rsa key")
		}
		eInt := new(big.Int).SetBytes(e)
		if !eInt.IsInt64() || eInt.Int64() > 1<<31-1 {
			return Public{}, errors.New("rsa exponent too large")
		}
		k := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(eInt.Int64())}
		if err := checkRSASize(k); err != nil {
			return Public{}, err
		}
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return Public{}, fmt.Errorf("rsa key: %w", err)
		}
		sum := md5.Sum(der) //nolint:gosec // EC2's format
		pub = Public{Type: resource.KeyTypeRSA, AWSFingerprint: ColonHex(hex.EncodeToString(sum[:]))}
	case "ssh-ed25519":
		key := r.str()
		if r.err || len(r.b) > 0 || len(key) != 32 {
			return Public{}, errors.New("malformed ssh-ed25519 key")
		}
		pub = Public{Type: resource.KeyTypeEd25519, AWSFingerprint: base64SHA256(string(blob))}
	default:
		return Public{}, fmt.Errorf("key algorithm %q is not ssh-rsa or ssh-ed25519", algo)
	}
	sum := sha256.Sum256(blob)
	pub.Fingerprint = hex.EncodeToString(sum[:])
	pub.Line = string(algo) + " " + base64.StdEncoding.EncodeToString(blob)
	if comment != "" {
		pub.Line += " " + comment
	}
	return pub, nil
}

func fromDER(der []byte) (Public, error) {
	var k *rsa.PublicKey
	if any, err := x509.ParsePKIXPublicKey(der); err == nil {
		rk, ok := any.(*rsa.PublicKey)
		if !ok {
			return Public{}, errors.New("DER keys must be RSA")
		}
		k = rk
	} else if rk, err := x509.ParsePKCS1PublicKey(der); err == nil {
		k = rk
	} else {
		return Public{}, errors.New("key is not OpenSSH, RFC 4716 or DER")
	}
	if err := checkRSASize(k); err != nil {
		return Public{}, err
	}
	blob := sshString("ssh-rsa") + sshString(string(mpint(big.NewInt(int64(k.E))))) + sshString(string(mpint(k.N)))
	return fromBlob([]byte(blob), "")
}

func checkRSASize(k *rsa.PublicKey) error {
	if bits := k.N.BitLen(); bits < minImportBits || bits > maxImportBits {
		return fmt.Errorf("rsa key is %d bits, want %d to %d", bits, minImportBits, maxImportBits)
	}
	return nil
}

// parseRFC4716 returns the blob in an SSH2 public key block, skipping
// headers and their backslash continuations.
func parseRFC4716(text string) ([]byte, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if strings.TrimSpace(lines[len(lines)-1]) != rfc4716End {
		return nil, errors.New("RFC 4716 block has no end line")
	}
	var b64 strings.Builder
	continued := false
	for _, line := range lines[1 : len(lines)-1] {
		line = strings.TrimSpace(line)
		switch {
		case continued:
			continued = strings.HasSuffix(line, "\\")
		case strings.Contains(line, ":"):
			continued = strings.HasSuffix(line, "\\")
		default:
			b64.WriteString(line)
		}
	}
	blob, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		return nil, errors.New("RFC 4716 body is not base64")
	}
	return blob, nil
}

type reader struct {
	b   []byte
	err bool
}

func (r *reader) str() []byte {
	if r.err || len(r.b) < 4 {
		r.err = true
		return nil
	}
	n := binary.BigEndian.Uint32(r.b)
	if uint64(n) > uint64(len(r.b)-4) {
		r.err = true
		return nil
	}
	s := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return s
}

// ColonHex writes lowercase hex as colon-separated byte pairs, as EC2 shows
// RSA fingerprints.
func ColonHex(h string) string {
	var out strings.Builder
	for i := 0; i+1 < len(h); i += 2 {
		if i > 0 {
			out.WriteByte(':')
		}
		out.WriteString(h[i : i+2])
	}
	return out.String()
}

func sha1Hex(b []byte) string {
	sum := sha1.Sum(b) //nolint:gosec // EC2's format
	return hex.EncodeToString(sum[:])
}

func base64SHA256(blob string) string {
	sum := sha256.Sum256([]byte(blob))
	return base64.StdEncoding.EncodeToString(sum[:])
}
