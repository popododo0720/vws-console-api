package regionhelper

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func fixture(t *testing.T) helper {
	t.Helper()
	base := t.TempDir()
	h := helper{
		public: base + "/public", private: base + "/private", locks: base + "/locks",
		snippets: base + "/snippets", kek: base + "/region-kek", owner: uint32(os.Geteuid()),
	}
	for _, dir := range []string{h.public, h.private, h.locks, h.snippets} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(h.kek, bytes.Repeat([]byte{42}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestCommandsAndConfinement(t *testing.T) {
	h := fixture(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, h.public+"/escape"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside+"/file", h.public+"/final"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		outside + "/file", h.public + "/../file",
		h.public + "/escape/file", h.public + "/final", h.public + "-other/file",
	} {
		t.Run(path, func(t *testing.T) {
			if err := confined(h.public, path); err == nil {
				t.Fatal("accepted escaping or symlink target")
			}
		})
	}
	if err := confined(h.public, h.public+"/registration.json"); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{},
		{"shell"},
		{"sh", "-c"},
		{"registration-write", outside},
		{"token-write", outside},
		{"lease-write", outside},
		{"lock", "../escape"},
		{"unlock", outside},
		{"snippet-write", "../escape"},
		{"snippet-delete", outside},
	} {
		if err := h.run(args, strings.NewReader("payload")); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
	for _, verb := range []string{"registration-write", "lease-write", "token-write"} {
		if err := h.run([]string{verb}, strings.NewReader("payload")); err != nil {
			t.Fatalf("%s: %v", verb, err)
		}
	}
	for _, name := range []string{"registration.json", "leader"} {
		st, err := os.Stat(filepath.Join(h.public, name))
		if err != nil || st.Mode().Perm() != 0o640 {
			t.Fatalf("public document is not readable: %v", err)
		}
	}
}

func TestSnippetNames(t *testing.T) {
	const good = "vws-01234567-89ab-cdef-0123-456789abcdef-user.yaml"
	for _, name := range []string{
		good, strings.ToUpper(good), "../" + good, "x/" + good,
		strings.ReplaceAll(good, "-", ""), "vws-not-a-uuid-user.yaml", good + ".bak",
	} {
		h := fixture(t)
		err := h.run([]string{"snippet-write", name}, strings.NewReader("cloud-init"))
		if (err == nil) != (name == good) {
			t.Fatalf("name %q: %v", name, err)
		}
		if name == good {
			if err := h.run([]string{"snippet-delete", name}, nil); err != nil {
				t.Fatal(err)
			}
			if err := h.run([]string{"snippet-delete", name}, nil); err != nil {
				t.Fatal("delete retry:", err)
			}
		}
	}
}

func TestTokenWriteEncrypted(t *testing.T) {
	h := fixture(t)
	plain := []byte("synthetic-PVE-token-never-on-disk")
	for range 2 {
		if err := h.run([]string{"token-write"}, bytes.NewReader(plain)); err != nil {
			t.Fatal(err)
		}
		sealed, err := os.ReadFile(h.private + "/pve-token")
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(sealed, plain) {
			t.Fatal("plaintext on disk")
		}
		key := bytes.Repeat([]byte{42}, 32)
		got, err := Open(key, sealed)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("open: %v", err)
		}
		if _, err := Open(bytes.Repeat([]byte{43}, 32), sealed); err == nil {
			t.Fatal("wrong KEK accepted")
		}
		for _, bad := range [][]byte{nil, sealed[:5], append([]byte{0}, sealed[1:]...)} {
			if _, err := Open(key, bad); err == nil {
				t.Fatal("corrupt envelope accepted")
			}
		}
		st, _ := os.Stat(h.private + "/pve-token")
		if st.Mode().Perm() != 0o600 {
			t.Fatal("private file mode:", st.Mode())
		}
	}
}

func TestAtomicRestartAndLocks(t *testing.T) {
	h := fixture(t)
	if err := h.run([]string{"registration-write"}, strings.NewReader("old")); err != nil {
		t.Fatal(err)
	}
	// A process killed before rename can leave an orphan; it must not become the target.
	os.WriteFile(h.public+"/.write-orphan", []byte("partial"), 0o600)
	for range 2 {
		if err := h.run([]string{"registration-write"}, strings.NewReader("new")); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := os.ReadFile(h.public + "/registration.json")
	if string(got) != "new" {
		t.Fatal("replacement failed")
	}
	if err := h.run([]string{"lock", "leader"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.run([]string{"lock", "leader"}, nil); err == nil {
		t.Fatal("duplicate lock acquired")
	}
	for range 2 {
		if err := h.run([]string{"unlock", "leader"}, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFailuresDoNotLeakContents(t *testing.T) {
	h := fixture(t)
	os.WriteFile(h.kek, []byte("secret-invalid-key"), 0o600)
	err := h.run([]string{"token-write"}, strings.NewReader("secret-token"))
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe error: %v", err)
	}
	var stderr bytes.Buffer
	if Main([]string{"secret-token"}, strings.NewReader("secret-body"), &bytes.Buffer{}, &stderr) == 0 ||
		strings.Contains(stderr.String(), "secret") {
		t.Fatal("unsafe CLI error")
	}
}

func TestCredentialConfigAndInputBoundary(t *testing.T) {
	h := fixture(t)
	for _, mode := range []os.FileMode{0o600, 0o644, 0o666} {
		os.Chmod(h.kek, mode)
		_, err := privateRead(h.kek, true, h.owner)
		if (err == nil) != (mode == 0o600) {
			t.Fatalf("credential mode %o: %v", mode, err)
		}
		_, err = privateRead(h.kek, false, h.owner)
		if (err == nil) != (mode != 0o666) {
			t.Fatalf("config mode %o: %v", mode, err)
		}
	}
	os.Chmod(h.kek, 0o600)
	os.Symlink(h.kek, h.kek+"-link")
	if _, err := privateRead(h.kek+"-link", true, h.owner); err == nil {
		t.Fatal("symlink credential accepted")
	}
	if err := h.run([]string{"registration-write"}, strings.NewReader("old")); err != nil {
		t.Fatal(err)
	}
	if err := h.run([]string{"registration-write"}, strings.NewReader(strings.Repeat("x", maxContents+1))); err == nil {
		t.Fatal("oversized input accepted")
	}
	got, _ := os.ReadFile(h.public + "/registration.json")
	if string(got) != "old" {
		t.Fatal("failed write changed target")
	}
}

func TestMain(m *testing.M) {
	if root := os.Getenv("VWS_HELPER_TEST_ROOT"); root != "" {
		if fail, err := os.ReadFile(root + "/fail"); err == nil && string(fail) == os.Args[1] {
			if os.Remove(root+"/fail") != nil {
				os.Exit(2)
			}
			os.Exit(1)
		}
		h := helper{
			public: root + "/public", private: root + "/private", locks: root + "/locks",
			kek: root + "/region-kek", owner: uint32(os.Geteuid()),
		}
		if err := h.execute(os.Args[1:], os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if path := os.Getenv("VWS_HELPER_TEST_CAPTURE"); path != "" {
		data, err := os.ReadFile("/dev/stdin")
		if err != nil {
			os.Exit(2)
		}
		record, err := json.Marshal([]string{strings.Join(os.Args[1:], "|"), string(data)})
		if err != nil || os.WriteFile(path, record, 0o600) != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestTokenReadAndCredentialFallback(t *testing.T) {
	h := fixture(t)
	plain := []byte("canary-token-read")
	if err := h.run([]string{"token-write"}, bytes.NewReader(plain)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := h.execute([]string{"token-read"}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), plain) {
		t.Fatal("token-read emitted plaintext")
	}
	got, err := Open(bytes.Repeat([]byte{42}, 32), out.Bytes())
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("token-read did not return the encrypted envelope")
	}
	out.Reset()
	if h.execute([]string{"token-read", h.private + "/pve-token"}, nil, &out) == nil || out.Len() != 0 {
		t.Fatal("token-read accepted arguments")
	}
	if credentialPath("") != "/etc/vws/credentials/region-kek" ||
		credentialPath("/run/credentials/vws-region.service") != "/run/credentials/vws-region.service/region-kek" {
		t.Fatal("incorrect KEK fallback or systemd credential path")
	}
}

func TestClientUsesFixedArgvAndStdin(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := Client{Path: binary}
	path := t.TempDir() + "/capture"
	t.Setenv("VWS_HELPER_TEST_CAPTURE", path)
	ctx := context.Background()
	const secret = "synthetic-secret"
	const snippet = "vws-123e4567-e89b-12d3-a456-426614174000-user.yaml"
	for _, tc := range []struct {
		argv string
		call func() error
	}{
		{"registration-write", func() error { return c.WriteRegistration(ctx, []byte(secret)) }},
		{"token-write", func() error { return c.WriteToken(ctx, []byte(secret)) }},
		{"lease-write", func() error { return c.WriteLease(ctx, []byte(secret)) }},
		{"lock|leader", func() error { return c.Lock(ctx, "leader") }},
		{"unlock|leader", func() error { return c.Unlock(ctx, "leader") }},
		{"snippet-write|" + snippet, func() error {
			return c.WriteSnippet(ctx, snippet, []byte(secret))
		}},
		{"snippet-delete|" + snippet, func() error { return c.DeleteSnippet(ctx, snippet) }},
	} {
		if err := tc.call(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		var record []string
		if err != nil || json.Unmarshal(data, &record) != nil || len(record) != 2 {
			t.Fatal("missing subprocess capture")
		}
		if record[0] != tc.argv || (strings.Contains(tc.argv, "write") && record[1] != secret) {
			t.Fatalf("unexpected subprocess input: %q", record)
		}
	}
}

func TestClientRejectsInvalidNamesBeforeExec(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := Client{Path: binary}
	path := t.TempDir() + "/capture"
	t.Setenv("VWS_HELPER_TEST_CAPTURE", path)
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"empty lock":     func() error { return c.Lock(ctx, "") },
		"dash lock":      func() error { return c.Lock(ctx, "-x") },
		"traversal":      func() error { return c.Unlock(ctx, "../a") },
		"bad snippet":    func() error { return c.WriteSnippet(ctx, "x.yaml", []byte("data")) },
		"empty snippet":  func() error { return c.DeleteSnippet(ctx, "") },
		"empty unlock":   func() error { return c.Unlock(ctx, "") },
		"traversal lock": func() error { return c.Lock(ctx, "a/b") },
	} {
		if err := call(); err == nil {
			t.Fatalf("%s: expected error", name)
		}
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("%s: helper was executed", name)
		}
	}
	if err := c.Lock(ctx, "leader"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("valid name did not execute helper")
	}
}

func TestNoShellAndTypedClient(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	for _, path := range files {
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		aliases := map[string]bool{}
		for _, imp := range f.Imports {
			if imp.Path.Value == `"os/exec"` {
				name := "exec"
				if imp.Name != nil {
					name = imp.Name.Name
				}
				aliases[name] = true
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || !aliases[pkg.Name] || (sel.Sel.Name != "Command" && sel.Sel.Name != "CommandContext") {
				return true
			}
			calls++
			for _, arg := range call.Args {
				if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					v, _ := strconv.Unquote(lit.Value)
					if v == "-c" || strings.HasSuffix(filepath.Base(v), "sh") {
						t.Errorf("shell exec in %s", path)
					}
				}
			}
			return true
		})
	}
	if calls != 1 {
		t.Fatalf("want one direct helper exec, got %d", calls)
	}
	c := Client{Path: "/does-not-exist"}
	if err := c.WriteToken(context.Background(), []byte("secret")); err == nil ||
		strings.Contains(err.Error(), "secret") {
		t.Fatalf("wrapper error: %v", err)
	}
}
