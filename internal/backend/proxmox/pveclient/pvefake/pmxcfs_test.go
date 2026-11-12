package pvefake_test

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestPMXCFSIsReadOnlyWithoutQuorum(t *testing.T) {
	f, _ := start(t, scenario(t))
	p := f.PMXCFS()
	lock := "/etc/pve/lock"
	file := lock + "/lease"
	if err := p.Mkdir(lock); err != nil {
		t.Fatal(err)
	}
	if err := p.Mkdir(lock); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("existing lock: %v", err)
	}
	data := []byte("owner")
	if err := p.WriteFile(file, data); err != nil {
		t.Fatal(err)
	}
	data[0] = 'X'
	read := func(want string) {
		t.Helper()
		got, err := f.PMXCFS().ReadFile(file)
		if err != nil || string(got) != want {
			t.Fatalf("lease=%q error=%v, want %q", got, err, want)
		}
		got[0] = 'X'
	}
	read("owner")
	if err := p.Remove(lock); err == nil {
		t.Fatal("removed non-empty lock")
	}
	if err := p.Mkdir("/etc/pve/empty"); err != nil {
		t.Fatal(err)
	}
	if err := p.Remove("/etc/pve/empty"); err != nil {
		t.Fatal(err)
	}
	f.SetQuorate(false)
	for name, mutate := range map[string]func() error{
		"replace": func() error { return p.WriteFile(file, []byte("new")) },
		"create":  func() error { return p.WriteFile(lock+"/new", []byte("new")) },
		"mkdir":   func() error { return p.Mkdir(lock + "/new") },
		"remove":  func() error { return p.Remove(file) },
	} {
		if err := mutate(); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("%s without quorum: %v", name, err)
		}
	}
	read("owner")
	if _, err := p.ReadFile(lock + "/new"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("quorum loss created a file: %v", err)
	}
	f.SetQuorate(true)
	if err := p.WriteFile(file, []byte("next")); err != nil {
		t.Fatal(err)
	}
	read("next")
	if err := p.Mkdir(lock + "/new"); err != nil {
		t.Fatalf("quorum loss created a directory: %v", err)
	}
	for _, name := range []string{lock + "/new", file, lock} {
		if err := p.Remove(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Remove(file); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing lease: %v", err)
	}
	for _, name := range []string{
		"/etc/pve-other/x", "/etc/pve/../x", "etc/pve/x", "/else", "/etc/pve/a\x00b",
		"/etc/pve/a\nb", "/etc/pve/a\tb", "/etc/pve/a\x7fb",
		"/etc/pve/" + strings.Repeat("n", 256), "/etc/pve" + strings.Repeat("/n", 2045),
	} {
		for _, err := range []error{
			p.WriteFile(name, nil), p.Mkdir(name), p.Remove(name),
		} {
			if pe, ok := errors.AsType[*fs.PathError](err); !ok || pe.Path != name || !errors.Is(err, fs.ErrInvalid) {
				t.Fatalf("invalid path %q: %v", name, err)
			}
		}
		if _, err := p.ReadFile(name); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("invalid read %q: %v", name, err)
		}
	}
	if err := p.Mkdir("/etc/pve/missing/child"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing parent: %v", err)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			name := fmt.Sprintf("/etc/pve/lease-%d", i)
			if err := p.WriteFile(name, []byte("lease")); err != nil {
				t.Error(err)
			}
			if _, err := p.ReadFile(name); err != nil {
				t.Error(err)
			}
			if err := p.Remove(name); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

func TestPowerRefusesWithoutQuorum(t *testing.T) {
	w := newTaskWorld(t)
	w.f.SetQuorate(false)
	for _, action := range []string{"start", "shutdown", "stop", "reboot"} {
		var env struct{ Message string }
		w.call(t, http.MethodPost, "/nodes/pve1/qemu/100/status/"+action, "alice@pve!one", 500, &env)
		if env.Message != "cluster not ready - no quorum?\n" {
			t.Fatalf("quorum failure: %q", env.Message)
		}
	}
	if rows := w.list(t, "source=all", auditor); len(rows) != 0 {
		t.Fatalf("quorum loss submitted tasks: %v", rows)
	}
	w.f.SetQuorate(true)
	if st := w.status(t, w.power(t, 100, "stop", "alice@pve!one")); st.ExitStatus != "OK" {
		t.Fatalf("restored quorum: %+v", st)
	}
}
