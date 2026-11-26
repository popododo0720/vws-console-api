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
func writeFileAtomic(dir, name string, data []byte, step func(stage string) error) error {
	return replaceFileAtomic(dir, name, data, step, nil)
}

// replaceFileAtomic is writeFileAtomic that calls beforeRename, when non-nil,
// with the synced temporary file just before it replaces dir/name; an error
// from it aborts the write and leaves dir/name as it was. The rename keeps the
// file's identity, so beforeRename sees the identity the new file will have.
func replaceFileAtomic(
	dir, name string, data []byte, step func(stage string) error, beforeRename func(tmp string) error,
) (err error) {
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
	if beforeRename != nil {
		if err := beforeRename(tmp); err != nil {
			return err
		}
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

// ensurePrivateDir makes dir a private state directory and returns its
// resolved absolute path; callers use only that path. The existing prefix of
// dir is resolved once with EvalSymlinks. Every component from / down is checked
// with Lstat: it must be a real directory, not a symlink, owned by root or this
// uid. Ancestors must not be group or other writable unless sticky, so no other
// user can replace an entry on the path. The final directory must be owned by
// this uid with no group or other access, and dir itself may not be a symlink.
// Missing components are created 0700 one at a time, each only after its parent
// passed and checked again before the next, so a refusal leaves nothing behind.
// Last, the final directory and every ancestor are fsynced on every call, so a
// sync that failed after a mkdir is redone by the next Open; any failure
// refuses the directory.
func ensurePrivateDir(dir string, sync func(string) error) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve state directory: %w", err)
	}
	if info, err := os.Lstat(dir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("state directory %s must not be a symlink", dir)
	}
	existing, rest := dir, []string{}
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect state directory: %w", err)
		}
		rest = append([]string{filepath.Base(existing)}, rest...)
		existing = filepath.Dir(existing)
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", fmt.Errorf("resolve state directory: %w", err)
	}
	parts := strings.Split(strings.TrimPrefix(resolved, "/"), "/")
	paths := []string{"/"}
	for i := range parts {
		if parts[i] != "" {
			paths = append(paths, filepath.Join("/", filepath.Join(parts[:i+1]...)))
		}
	}
	for i, p := range paths {
		if err := checkStateComponent(p, i == len(paths)-1 && len(rest) == 0); err != nil {
			return "", err
		}
	}
	for i, name := range rest {
		resolved = filepath.Join(resolved, name)
		if err := os.Mkdir(resolved, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("create state directory: %w", err)
		}
		if err := checkStateComponent(resolved, i == len(rest)-1); err != nil {
			return "", err
		}
		paths = append(paths, resolved)
	}
	for i := len(paths) - 1; i >= 0; i-- {
		if err := sync(paths[i]); err != nil {
			return "", err
		}
	}
	return resolved, nil
}

// checkStateComponent validates one component of the resolved state path with
// Lstat; see ensurePrivateDir for the rules.
func checkStateComponent(p string, final bool) error {
	info, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", p, err)
	}
	uid, ok := owner(info)
	switch {
	case !info.IsDir() || !ok:
		return fmt.Errorf("%s on the state directory path must be a real directory, not a symlink", p)
	case final && (uid != os.Geteuid() || info.Mode().Perm()&0o077 != 0):
		return fmt.Errorf("state directory %s must be owned by this user with mode 0700", p)
	case !final && (uid != 0 && uid != os.Geteuid() ||
		info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0):
		return fmt.Errorf("ancestor %s of the state directory must be owned by root or this user "+
			"and not writable by group or others unless sticky", p)
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
