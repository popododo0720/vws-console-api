package regionhelper

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestTokenDeleteRefusesLiveBackup(t *testing.T) {
	h := fixture(t)
	const secret = "helper-backup-canary"
	fp := fmt.Sprintf("%x", sha256.Sum256([]byte(secret)))
	if err := h.run([]string{"token-write", fp}, strings.NewReader(secret)); err != nil {
		t.Fatal(err)
	}
	identity := `{"fingerprint":"` + strings.Repeat("0", 64) + `","backupFingerprint":"` + fp + `"}`
	if err := h.run([]string{"registration-write"}, strings.NewReader(identity)); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := h.run([]string{"token-delete", fp}, nil); err == nil {
			t.Fatal("deleted live backup token")
		}
		sealed, err := os.ReadFile(h.private + "/pve-token." + fp)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := Open(bytes.Repeat([]byte{42}, 32), sealed)
		if err != nil || string(plain) != secret {
			t.Fatal("refusal damaged live backup token")
		}
	}
}
