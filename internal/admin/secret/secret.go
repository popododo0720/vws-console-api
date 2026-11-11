// Package secret seals admin credentials under the global AES-256-GCM KEK.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Sealed follows the IAM seal layout: a key id and nonce-prefixed ciphertext.
type Sealed struct {
	KeyID      string `json:"keyId"`
	Ciphertext []byte `json:"ciphertext"`
}

// Key seals credentials and authenticates their owning account id.
type Key struct {
	id   string
	aead cipher.AEAD
}

// New takes a KEK id and exactly 32 key bytes.
func New(id string, key []byte) (*Key, error) {
	if !regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`).MatchString(id) || len(key) != 32 {
		return nil, errors.New("admin KEK requires a valid id and 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("admin KEK cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("admin KEK GCM: %w", err)
	}
	return &Key{id: id, aead: aead}, nil
}

// LoadFile reads the IAM KEK format, base64 of 32 bytes; the filename is its id.
func LoadFile(path string) (*Key, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-selected systemd credential.
	if err != nil {
		return nil, fmt.Errorf("read admin KEK: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, errors.New("admin KEK is not base64")
	}
	return New(filepath.Base(path), key)
}

// Seal binds plaintext to account, using the IAM key-id/AAD layout.
func (k *Key) Seal(plaintext []byte, account string) (Sealed, error) {
	nonce := make([]byte, k.aead.NonceSize(), k.aead.NonceSize()+len(plaintext)+k.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, fmt.Errorf("admin secret nonce: %w", err)
	}
	return Sealed{KeyID: k.id, Ciphertext: k.aead.Seal(nonce, nonce, plaintext, []byte(k.id+"\x00"+account))}, nil
}

// Open refuses ciphertext moved to another account or changed after sealing.
func (k *Key) Open(s Sealed, account string) ([]byte, error) {
	n := k.aead.NonceSize()
	if s.KeyID != k.id || len(s.Ciphertext) < n+k.aead.Overhead() {
		return nil, errors.New("cannot open admin secret")
	}
	plain, err := k.aead.Open(nil, s.Ciphertext[:n], s.Ciphertext[n:], []byte(k.id+"\x00"+account))
	if err != nil {
		return nil, errors.New("cannot open admin secret")
	}
	return plain, nil
}
