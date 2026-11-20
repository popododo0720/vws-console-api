package proxmox

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestWriteFileAtomicIs0600AndDurable(t *testing.T) {
	dir := t.TempDir()
	var stages []string
	record := func(stage string) error { stages = append(stages, stage); return nil }
	if err := writeFileAtomic(dir, "state.json", []byte("one"), record); err != nil {
		t.Fatal(err)
	}
	if want := []string{"create", "write", "sync", "close", "rename", "syncdir"}; !slices.Equal(stages, want) {
		t.Fatalf("stages = %v, want %v", stages, want)
	}
	info, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode: %v, %v", info, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("directory after write: %v %v", entries, err)
	}
}

func TestWriteFileAtomicCrashLeavesOldOrNew(t *testing.T) {
	for _, crashAt := range []string{"create", "write", "sync", "close", "rename", "syncdir"} {
		t.Run(crashAt, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state.json")
			if err := writeFileAtomic(dir, "state.json", []byte("old"), nil); err != nil {
				t.Fatal(err)
			}
			crash := errors.New("crash")
			err := writeFileAtomic(dir, "state.json", []byte("new"), func(stage string) error {
				if stage == crashAt {
					return crash
				}
				return nil
			})
			if !errors.Is(err, crash) {
				t.Fatalf("err = %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			// The rename is the commit point: before it the file is old, after it new.
			want := "old"
			if crashAt == "syncdir" {
				want = "new"
			}
			if string(got) != want {
				t.Fatalf("after crash at %s the file is %q, want %q", crashAt, got, want)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("failed write left files: %v %v", entries, err)
			}
		})
	}
}

func TestOpenRemovesTemporaryFileOfACrashedWrite(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "region.yaml")
	writeFixture(t, config, []byte("read_only: true\n"))
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(state, registrationFile), []byte(`{"region":"pve-test-1","cluster_name":"test",`+
		`"tokenId":"vws@pve!inventory","token":"fake-secret"}`))
	torn := filepath.Join(state, "."+registrationFile+".tmp-123")
	writeFixture(t, torn, []byte(`{"region":"pve-te`))
	c, err := Open(config, "pve-test-1", state, "https://unused", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(torn); !os.IsNotExist(err) {
		t.Fatalf("temporary file survived Open: %v", err)
	}
	if s, _, err := c.registration(); err != nil || s.Token != "fake-secret" {
		t.Fatalf("old file not intact: %v", err)
	}
}

func TestOpenRequiresAPrivateStateDirectory(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "region.yaml")
	writeFixture(t, config, []byte("read_only: true\n"))
	for _, mode := range []os.FileMode{0o777, 0o770, 0o750, 0o707} {
		state := filepath.Join(dir, "shared")
		if err := os.Mkdir(state, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(state, mode); err != nil {
			t.Fatal(err)
		}
		stale := filepath.Join(state, "."+registrationFile+".tmp-1")
		writeFixture(t, stale, []byte("x"))
		if _, err := Open(config, "pve-test-1", state, "https://unused", nil); err == nil {
			t.Fatalf("accepted state directory with mode %o", mode)
		}
		if _, err := os.Stat(stale); err != nil {
			t.Fatalf("mode %o: files were touched before the check: %v", mode, err)
		}
		if err := os.RemoveAll(state); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(config, "pve-test-1", link, "https://unused", nil); err == nil {
		t.Fatal("accepted a symlinked state directory")
	}
}

func TestOpenCreatesNestedStateDirectoryPrivately(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "region.yaml")
	writeFixture(t, config, []byte("read_only: true\n"))
	state := filepath.Join(dir, "a", "b", "state")
	if _, err := Open(config, "pve-test-1", state, "https://unused", nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{state, filepath.Dir(state), filepath.Dir(filepath.Dir(state))} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v, %v", p, info, err)
		}
	}
	if _, err := Open(config, "pve-test-1", state, "https://unused", nil); err != nil {
		t.Fatalf("reopening an existing private directory: %v", err)
	}
}
