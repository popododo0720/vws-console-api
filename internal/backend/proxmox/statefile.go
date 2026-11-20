package proxmox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// writeFileAtomic replaces dir/name with data. The data goes to a 0600
// temporary file in the same directory, the file is fsynced, renamed over the
// target and the directory is fsynced. A crash at any point leaves the old file
// or the new one, never a partial file. step, when non-nil, is called before
// each stage and aborts the write by returning an error; tests use it.
func writeFileAtomic(dir, name string, data []byte, step func(stage string) error) (err error) {
	at := func(stage string) error {
		if step == nil {
			return nil
		}
		return step(stage)
	}
	if err := at("create"); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmp := f.Name()
	closed := false
	defer func() {
		if err == nil {
			return
		}
		if !closed {
			_ = f.Close() //nolint:errcheck // already failing; the write error is returned
		}
		if rmErr := os.Remove(tmp); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			err = errors.Join(err, rmErr)
		}
	}()
	for _, stage := range []string{"write", "sync"} {
		if err := at(stage); err != nil {
			return err
		}
		if stage == "write" {
			_, err = f.Write(data)
		} else {
			err = f.Sync()
		}
		if err != nil {
			return fmt.Errorf("%s temporary file: %w", stage, err)
		}
	}
	if err := at("close"); err != nil {
		return err
	}
	closed = true
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := at("rename"); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("replace %s: %w", name, err)
	}
	if err := at("syncdir"); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open directory %s: %w", dir, err)
	}
	if err := errors.Join(d.Sync(), d.Close()); err != nil {
		return fmt.Errorf("sync directory %s: %w", dir, err)
	}
	return nil
}

// ensurePrivateDir makes dir a private state directory: created 0700 with any
// missing parents, owned by this uid, a real directory (not a symlink), with no
// group or other access. Every ancestor up to / must be owned by root or this
// uid and either not group/other writable or sticky, so no other user can
// replace an entry on the path. Then dir and every ancestor are fsynced on every
// call, so a sync that failed after a mkdir is redone by the next Open; any
// failure refuses the directory.
func ensurePrivateDir(dir string, sync func(string) error) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve state directory: %w", err)
	}
	var missing []string
	for p := dir; ; p = filepath.Dir(p) {
		_, err := os.Lstat(p)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect state directory: %w", err)
		}
		missing = append(missing, p)
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.Mkdir(missing[i], 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create state directory: %w", err)
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}
	if uid, ok := owner(info); !info.IsDir() || !ok || uid != os.Geteuid() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state directory %s must be a real directory owned by this user with mode 0700", dir)
	}
	for p := filepath.Dir(dir); ; p = filepath.Dir(p) {
		info, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("inspect ancestor %s: %w", p, err)
		}
		uid, ok := owner(info)
		if !ok || uid != 0 && uid != os.Geteuid() ||
			info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("ancestor %s of the state directory must be owned by root or this user "+
				"and not writable by group or others unless sticky", p)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	for p := dir; ; p = filepath.Dir(p) {
		if err := sync(p); err != nil {
			return err
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}

func owner(info os.FileInfo) (int, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// removeStaleTemps deletes temporary files a crashed write left behind.
func removeStaleTemps(dir, name string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("proxmox: read state dir: %w", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "."+name+".tmp-") {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("proxmox: remove stale temporary file: %w", err)
			}
		}
	}
	return nil
}
