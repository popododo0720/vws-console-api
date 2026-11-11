package secret_test

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/admin/secret"
)

func TestAccountSeal(t *testing.T) {
	k, err := secret.New("global", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := k.Seal([]byte("distinctive-external-id"), "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	p, err := k.Open(s, "123456789012")
	if err != nil || string(p) != "distinctive-external-id" {
		t.Fatalf("round trip: %q %v", p, err)
	}
	other, err := secret.New("global", bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		key  *secret.Key
		aad  string
		edit func(*secret.Sealed)
	}{
		{"tamper", k, "123456789012", func(s *secret.Sealed) { s.Ciphertext[len(s.Ciphertext)-1] ^= 1 }},
		{"wrong-aad", k, "000000000000", func(*secret.Sealed) {}},
		{"wrong-kek", other, "123456789012", func(*secret.Sealed) {}},
		{"short", k, "123456789012", func(s *secret.Sealed) { s.Ciphertext = s.Ciphertext[:1] }},
		{"key-id", k, "123456789012", func(s *secret.Sealed) { s.KeyID = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := s
			v.Ciphertext = bytes.Clone(s.Ciphertext)
			tc.edit(&v)
			if _, err := tc.key.Open(v, tc.aad); err == nil {
				t.Fatal("invalid seal opened")
			}
		})
	}
}

func TestKEKFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "global")
	if _, err := secret.LoadFile(path); err == nil {
		t.Fatal("missing KEK accepted")
	}
	for _, value := range []string{"canary-invalid-key!", "AAAA", base64.StdEncoding.EncodeToString(make([]byte, 32))} {
		if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := secret.LoadFile(path)
		if len(value) == 44 {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil || strings.Contains(err.Error(), value) {
			t.Fatalf("bad KEK accepted or disclosed: %v", err)
		}
	}
	if _, err := secret.New("bad/id", make([]byte, 32)); err == nil {
		t.Fatal("bad KEK id accepted")
	}
}
