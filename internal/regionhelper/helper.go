// Package regionhelper confines the region daemon's privileged file operations.
package regionhelper

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const (
	publicRoot  = "/etc/pve/vws"
	privateRoot = "/etc/pve/priv/vws"
	lockRoot    = "/etc/pve/priv/lock/vws-region"
	snippetFile = "/etc/vws/region-helper-snippets"
	header      = "VWS-TOKEN\x01"
	maxContents = 1 << 20
)

type helper struct {
	public, private, locks, snippets, kek string
	owner                                 uint32
}

// Main implements the fixed helper CLI. Contents are read only from stdin.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	h := helper{
		public: publicRoot, private: privateRoot, locks: lockRoot,
		kek: credentialPath(os.Getenv("CREDENTIALS_DIRECTORY")),
	}
	if err := h.execute(args, stdin, stdout); err != nil {
		if _, writeErr := fmt.Fprintln(stderr, "vws-region-helper: operation refused"); writeErr != nil {
			return 1
		}
		return 1
	}
	return 0
}

func credentialPath(dir string) string {
	if dir == "" {
		return "/etc/vws/credentials/region-kek"
	}
	return filepath.Join(dir, "region-kek")
}

func (h helper) execute(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) != 0 && args[0] == "token-read" {
		if len(args) != 2 || !validFingerprint(args[1]) {
			return errors.New("unexpected arguments")
		}
		data, err := privateRead(filepath.Join(h.private, "pve-token."+args[1]), true, h.owner)
		if err != nil {
			return err
		}
		if !bytes.HasPrefix(data, []byte(header)) {
			return errors.New("invalid token envelope")
		}
		if _, err := stdout.Write(data); err != nil {
			return fmt.Errorf("write token envelope: %w", err)
		}
		return nil
	}
	return h.run(args, stdin)
}

func validLockName(s string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`).MatchString(s)
}

func validFingerprint(s string) bool {
	return regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s)
}

func validSnippetName(s string) bool {
	return regexp.MustCompile(
		`^vws-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-user\.yaml$`,
	).MatchString(s)
}

func (h helper) run(args []string, stdin io.Reader) (err error) {
	if len(args) == 0 {
		return errors.New("missing operation")
	}
	root, name, write, encrypt := "", "", false, false
	switch args[0] {
	case "registration-write":
		root, name, write = h.public, "registration.json", true
	case "token-write", "token-delete":
		if len(args) != 2 || !validFingerprint(args[1]) {
			return errors.New("invalid token fingerprint")
		}
		root, name = h.private, "pve-token."+args[1]
		write, encrypt = args[0] == "token-write", args[0] == "token-write"
		if !write {
			locks, openErr := os.OpenRoot(h.locks)
			if openErr != nil {
				return fmt.Errorf("open registration lock root: %w", openErr)
			}
			defer func() { err = errors.Join(err, locks.Close()) }()
			if err := locks.Mkdir("registration", 0o700); err != nil {
				return fmt.Errorf("acquire registration lock: %w", err)
			}
			defer func() { err = errors.Join(err, locks.Remove("registration")) }()
			path := filepath.Join(h.public, "registration.json")
			f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return errors.New("registration unreadable")
			}
			if err == nil {
				info, statErr := f.Stat()
				data, readErr := io.ReadAll(io.LimitReader(f, (65<<10)+1))
				var identity struct {
					Fingerprint string `json:"fingerprint"`
				}
				if err := errors.Join(statErr, readErr, f.Close()); err != nil || !info.Mode().IsRegular() || len(data) > 65<<10 ||
					json.Unmarshal(data, &identity) != nil || !validFingerprint(identity.Fingerprint) {
					return errors.New("invalid registration identity")
				}
				if identity.Fingerprint == args[1] {
					return errors.New("cannot delete active token")
				}
			}
		}
	case "lease-write":
		root, name, write = h.public, "leader", true
	case "lock", "unlock":
		if len(args) != 2 || !validLockName(args[1]) {
			return errors.New("invalid lock name")
		}
		root, name = h.locks, args[1]
	case "snippet-write", "snippet-delete":
		if len(args) != 2 || !validSnippetName(args[1]) {
			return errors.New("invalid snippet name")
		}
		root = h.snippets
		if root == "" {
			data, err := privateRead(snippetFile, false, h.owner)
			if err != nil {
				return err
			}
			root = strings.TrimSpace(string(data))
		}
		name, write = args[1], args[0] == "snippet-write"
	default:
		return errors.New("unknown operation")
	}
	if (args[0] == "registration-write" || args[0] == "lease-write") && len(args) != 1 {
		return errors.New("unexpected arguments")
	}
	if err := confined(root, filepath.Join(root, name)); err != nil {
		return err
	}
	dir, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("open operation root: %w", err)
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	if !write {
		if args[0] == "lock" {
			if err := dir.Mkdir(name, 0o700); err != nil {
				return fmt.Errorf("acquire lock: %w", err)
			}
			return nil
		}
		if args[0] == "unlock" {
			st, err := dir.Lstat(name)
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil || !st.IsDir() {
				return errors.New("lock is not a directory")
			}
		}
		if err := dir.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove target: %w", err)
		}
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(stdin, maxContents+1))
	if err != nil || len(data) > maxContents {
		return errors.New("cannot read bounded input")
	}
	if encrypt {
		if fmt.Sprintf("%x", sha256.Sum256(data)) != args[1] {
			return errors.New("token fingerprint mismatch")
		}
		key, err := privateRead(h.kek, true, h.owner)
		if err != nil {
			return err
		}
		data, err = seal(key, data)
		if err != nil {
			return err
		}
	}
	mode := os.FileMode(0o600)
	if root == h.public {
		mode = 0o640
	}
	return atomicWrite(dir, name, data, mode)
}

func confined(root, target string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !filepath.IsAbs(target) {
		return errors.New("invalid root or target")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve root: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(target))
	if err != nil {
		return fmt.Errorf("resolve target parent: %w", err)
	}
	rel, err := filepath.Rel(resolvedRoot, filepath.Join(parent, filepath.Base(target)))
	if err != nil || !filepath.IsLocal(rel) || rel == "." {
		return errors.New("target outside root")
	}
	st, err := os.Lstat(target)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect target: %w", err)
	}
	if err == nil && st.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlink target refused")
	}
	return nil
}

func privateRead(path string, secret bool, uid uint32) (data []byte, err error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("credential or config path is not absolute")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open credential or config")
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	st, err := f.Stat()
	if err != nil {
		return nil, errors.New("cannot inspect credential or config")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uid || !st.Mode().IsRegular() || st.Mode().Perm()&0o022 != 0 ||
		(secret && st.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("unsafe credential or config permissions")
	}
	data, err = io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return nil, errors.New("cannot read bounded credential or config")
	}
	return data, nil
}

func atomicWrite(dir *os.Root, name string, data []byte, mode os.FileMode) (err error) {
	entropy := make([]byte, 16)
	if _, err := rand.Read(entropy); err != nil {
		return fmt.Errorf("temporary name entropy: %w", err)
	}
	tmp := ".write-" + hex.EncodeToString(entropy)
	f, err := dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	defer func() {
		if removeErr := dir.Remove(tmp); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove temporary file: %w", removeErr))
		}
	}()
	_, writeErr := f.Write(data)
	err = errors.Join(writeErr, f.Chmod(mode), f.Sync(), f.Close())
	if err != nil {
		return fmt.Errorf("persist temporary file: %w", err)
	}
	if err := dir.Rename(tmp, name); err != nil {
		return fmt.Errorf("replace target: %w", err)
	}
	return nil
}

func envelope(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("KEK must contain 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize envelope: %w", err)
	}
	return aead, nil
}

func seal(key, data []byte) ([]byte, error) {
	aead, err := envelope(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce entropy: %w", err)
	}
	out := append([]byte(header), nonce...)
	return aead.Seal(out, nonce, data, []byte(header)), nil
}

// Open authenticates a versioned token envelope with the region KEK.
func Open(key, sealed []byte) ([]byte, error) {
	aead, err := envelope(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < len(header)+aead.NonceSize()+aead.Overhead() || string(sealed[:len(header)]) != header {
		return nil, errors.New("invalid token envelope")
	}
	nonce := sealed[len(header) : len(header)+aead.NonceSize()]
	data, err := aead.Open(nil, nonce, sealed[len(header)+len(nonce):], []byte(header))
	if err != nil {
		return nil, errors.New("token authentication failed")
	}
	return data, nil
}
