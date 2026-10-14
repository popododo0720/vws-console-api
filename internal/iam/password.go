package iam

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// argon2id parameters: OWASP's minimum (19 MiB, t=2, p=1).
const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16

	minPasswordLen = 8
	maxPasswordLen = 128
)

// checkPassword is the account password policy: 8 to 128 characters.
func checkPassword(pw string) error {
	if n := utf8.RuneCountInString(pw); n < minPasswordLen || n > maxPasswordLen || !utf8.ValidString(pw) {
		return &resource.Error{Code: resource.CodeInvalidArgument, Field: "Password", Message: "Password should have a minimum length of 8"}
	}
	return nil
}

// hashPassword returns a PHC string: $argon2id$v=19$m=..,t=..,p=..$salt$key.
func hashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password salt: %w", err)
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// verifyPassword checks pw against a PHC hash in constant time. A malformed
// hash never matches.
func verifyPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return false
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || t == 0 || p == 0 || m > 1<<20 || t > 10 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[4])
	want, err2 := enc.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 || len(want) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want))) //nolint:gosec // len(want) <= 64.
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is verified against when the user or profile does not exist, so
// a failed login costs the same time either way. It is a hash of random bytes
// nobody knows; it is computed once per process.
func newDummyHash() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	h, err := hashPassword(base64.StdEncoding.EncodeToString(b))
	if err != nil {
		return "$argon2id$invalid"
	}
	return h
}
