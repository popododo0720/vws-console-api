package proxmox

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestWriteFileAtomicIs0600AndDurable(t *testing.T) {
	dir := privateDir(t)
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
			dir := privateDir(t)
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
	dir := privateDir(t)
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
	dir := privateDir(t)
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
	dir := privateDir(t)
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

// privateDir is t.TempDir with mode 0700; t.TempDir's own mode follows the umask.
func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestOpenRejectsAnUnsafeAncestor(t *testing.T) {
	root := privateDir(t)
	config := filepath.Join(root, "region.yaml")
	writeFixture(t, config, []byte("read_only: true\n"))
	open := func(parentMode os.FileMode) error {
		parent := filepath.Join(root, "parent")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.RemoveAll(parent); err != nil {
				t.Error(err)
			}
		}()
		if err := os.Chmod(parent, parentMode); err != nil {
			t.Fatal(err)
		}
		_, err := Open(config, "pve-test-1", filepath.Join(parent, "state"), "https://unused", nil)
		if err != nil && parentMode&0o022 != 0 && parentMode&os.ModeSticky == 0 {
			if entries, readErr := os.ReadDir(parent); readErr != nil || len(entries) != 0 {
				t.Errorf("rejection under mode %o left entries: %v %v", parentMode, entries, readErr)
			}
		}
		return err
	}
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
		err := open(mode)
		if err == nil || !strings.Contains(err.Error(), "parent") {
			t.Fatalf("accepted an ancestor with mode %o: %v", mode, err)
		}
	}
	if err := open(0o777 | os.ModeSticky); err != nil {
		t.Fatalf("refused a sticky ancestor: %v", err)
	}
	if err := open(0o755); err != nil {
		t.Fatalf("refused a 0755 ancestor: %v", err)
	}
}

func TestEnsurePrivateDirRedoesAFailedSync(t *testing.T) {
	base := privateDir(t)
	state := filepath.Join(base, "a", "state")
	var synced []string
	failOnce := true
	sync := func(p string) error {
		if failOnce && p == filepath.Dir(state) {
			failOnce = false
			return errors.New("sync failed")
		}
		synced = append(synced, p)
		return nil
	}
	if _, err := ensurePrivateDir(state, sync); err == nil {
		t.Fatal("a failed sync did not fail")
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatalf("mkdir did not happen before the sync: %v", err)
	}
	synced = nil
	if _, err := ensurePrivateDir(state, sync); err != nil {
		t.Fatal(err)
	}
	if len(synced) < 3 || synced[0] != state || synced[1] != filepath.Dir(state) || synced[len(synced)-1] != "/" {
		t.Fatalf("retry synced %v; want the state dir and every ancestor up to /", synced)
	}
}

func TestOpenResolvesSymlinkedAncestors(t *testing.T) {
	root := privateDir(t)
	config := filepath.Join(root, "region.yaml")
	writeFixture(t, config, []byte("read_only: true\n"))
	safe := filepath.Join(root, "safe")
	unsafe := filepath.Join(root, "unsafe")
	for dir, mode := range map[string]os.FileMode{safe: 0o700, unsafe: 0o700} {
		if err := os.Mkdir(dir, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"to-safe": safe, "to-unsafe": unsafe} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	nested := filepath.Join(root, "to-unsafe", "a", "state")
	if _, err := Open(config, "pve-test-1", nested, "https://unused", nil); err == nil {
		t.Fatal("accepted a symlinked ancestor that resolves to a group/other writable directory")
	}
	if entries, err := os.ReadDir(unsafe); err != nil || len(entries) != 0 {
		t.Fatalf("rejection left entries under the unsafe target: %v %v", entries, err)
	}
	c, err := Open(config, "pve-test-1", filepath.Join(root, "to-safe", "state"), "https://unused", nil)
	if err != nil {
		t.Fatalf("refused a symlinked ancestor with a safe target: %v", err)
	}
	want, err := filepath.EvalSymlinks(filepath.Join(safe, "state"))
	if err != nil || c.dir != want {
		t.Fatalf("state I/O dir = %q, want the resolved %q (%v)", c.dir, want, err)
	}
	if err := writeFileAtomic(c.dir, registrationFile, []byte("{}"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(safe, "state", registrationFile)); err != nil {
		t.Fatalf("state was not written under the resolved path: %v", err)
	}
	target := filepath.Join(safe, "state")
	link := filepath.Join(root, "final-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(config, "pve-test-1", link, "https://unused", nil); err == nil {
		t.Fatal("accepted a final directory that is a symlink")
	}
}
