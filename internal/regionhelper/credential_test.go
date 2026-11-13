package regionhelper

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestClientSystemdCredentialPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "region-kek")
	key := bytes.Repeat([]byte{42}, 32)
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	client := Client{}
	for _, mode := range []os.FileMode{0o400, 0o440, 0o600, 0o640, 0o444, 0o460, 0o450, 0o604, 0o602} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		wantOK := mode == 0o400 || mode == 0o440 || mode == 0o600 || mode == 0o640
		got, err := client.readKey(dir, uid)
		if (err == nil) != wantOK || (err == nil && !bytes.Equal(got, key)) {
			t.Fatalf("mode %o: key=%x err=%v", mode, got, err)
		}
	}
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := client.readKey(dir, uid+1); err == nil {
		t.Fatal("foreign credential directory owner accepted")
	}
	if _, err := privateRead(path, true, uid+1); err == nil {
		t.Fatal("foreign credential file owner accepted")
	}
	for _, mode := range []os.FileMode{0o720, 0o702} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := client.readKey(dir, uid); err == nil {
			t.Fatalf("writable credential directory %o accepted", mode)
		}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, dir+"-link"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(dir + "-link") })
	if _, err := client.readKey(dir+"-link", uid); err == nil {
		t.Fatal("symlink credential directory accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(target, key, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := client.readKey(dir, uid); err == nil {
		t.Fatal("symlink credential accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := client.readKey(dir, uid); err == nil {
		t.Fatal("non-regular credential accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{42}, 4097), 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := client.readKey(dir, uid); err == nil {
		t.Fatal("oversized credential accepted")
	}
}

func TestClientFallbackCredentialPermissions(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc/vws/credentials")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "region-kek")
	key := bytes.Repeat([]byte{42}, 32)
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}
	client := Client{Root: root}
	for _, mode := range []os.FileMode{0o600, 0o440, 0o640, 0o604, 0o644} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		got, err := client.readKey("", uint32(os.Geteuid()))
		if (err == nil) != (mode == 0o600) || (err == nil && !bytes.Equal(got, key)) {
			t.Fatalf("fallback mode %o: key=%x err=%v", mode, got, err)
		}
		if _, err := privateRead(path, true, uint32(os.Geteuid())); (err == nil) != (mode == 0o600) {
			t.Fatalf("helper mode %o: %v", mode, err)
		}
	}
}
