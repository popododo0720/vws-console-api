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

// ensurePrivateDir creates dir (and missing parents) with mode 0700, fsyncing
// the parent of every directory it creates so the entry survives power loss.
// It refuses an existing dir that is a symlink, is not owned by this uid, or
// has any group or other access.
func ensurePrivateDir(dir string) error {
	dir = filepath.Clean(dir)
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
		if filepath.Dir(p) == p {
			break
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.Mkdir(missing[i], 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create state directory: %w", err)
		}
		if err := syncDir(filepath.Dir(missing[i])); err != nil {
			return err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || int(owner.Uid) != os.Geteuid() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state directory %s must be a real directory owned by this user with mode 0700", dir)
	}
	return nil
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
