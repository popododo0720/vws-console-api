package pvefake

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// PMXCFS is an in-memory /etc/pve sharing its Fake's quorum and lock.
type PMXCFS struct {
	f *Fake
}

type pmxcfsEntry struct {
	dir  bool
	data []byte
}

// PMXCFS returns a handle to this fake's shared filesystem.
func (f *Fake) PMXCFS() *PMXCFS { return &PMXCFS{f: f} }

func validPMXCFSPath(name string) bool {
	return path.Clean(name) == name && !strings.ContainsRune(name, 0) &&
		(name == "/etc/pve" || strings.HasPrefix(name, "/etc/pve/"))
}

// ReadFile returns a copy of a file, including while quorum is absent.
func (p *PMXCFS) ReadFile(name string) ([]byte, error) {
	p.f.mu.RLock()
	defer p.f.mu.RUnlock()
	if !validPMXCFSPath(name) {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrInvalid}
	}
	entry, ok := p.f.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrNotExist}
	}
	if entry.dir {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrInvalid}
	}
	return bytes.Clone(entry.data), nil
}

// WriteFile atomically replaces a file with a copy of data.
func (p *PMXCFS) WriteFile(name string, data []byte) error {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	if err := p.writable(name); err != nil {
		return &fs.PathError{Op: "write", Path: name, Err: err}
	}
	if p.f.files[name].dir {
		return &fs.PathError{Op: "write", Path: name, Err: fs.ErrInvalid}
	}
	if err := p.parent(name); err != nil {
		return &fs.PathError{Op: "write", Path: name, Err: err}
	}
	p.f.files[name] = pmxcfsEntry{data: bytes.Clone(data)}
	return nil
}

// Mkdir creates a directory only when its parent exists.
func (p *PMXCFS) Mkdir(name string) error {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	if err := p.writable(name); err != nil {
		return &fs.PathError{Op: "mkdir", Path: name, Err: err}
	}
	if _, ok := p.f.files[name]; ok {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrExist}
	}
	if err := p.parent(name); err != nil {
		return &fs.PathError{Op: "mkdir", Path: name, Err: err}
	}
	p.f.files[name] = pmxcfsEntry{dir: true}
	return nil
}

// Remove refuses non-empty directories.
func (p *PMXCFS) Remove(name string) error {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	if err := p.writable(name); err != nil {
		return &fs.PathError{Op: "remove", Path: name, Err: err}
	}
	if _, ok := p.f.files[name]; !ok {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrNotExist}
	}
	for other := range p.f.files {
		if strings.HasPrefix(other, name+"/") {
			return &fs.PathError{Op: "remove", Path: name, Err: fmt.Errorf("directory not empty: %w", fs.ErrInvalid)}
		}
	}
	delete(p.f.files, name)
	return nil
}

func (p *PMXCFS) writable(name string) error {
	if !validPMXCFSPath(name) {
		return fs.ErrInvalid
	}
	if !p.f.quorate {
		return fs.ErrPermission
	}
	return nil
}

func (p *PMXCFS) parent(name string) error {
	if name == "/etc/pve" {
		return nil
	}
	entry, ok := p.f.files[path.Dir(name)]
	if !ok {
		return fs.ErrNotExist
	}
	if !entry.dir {
		return fs.ErrInvalid
	}
	return nil
}
