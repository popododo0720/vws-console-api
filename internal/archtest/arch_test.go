// Package archtest enforces the import boundaries in AGENTS.md.
package archtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	module   = "github.com/popododo0720/vws-console-api"
	vwsProto = "github.com/popododo0720/vws-proto"
)

func hasPrefix(prefixes ...string) func(string) bool {
	return func(s string) bool {
		for _, p := range prefixes {
			if s == p || strings.HasPrefix(s, p+"/") {
				return true
			}
		}
		return false
	}
}

func under(dir string, roots ...string) bool {
	for _, r := range roots {
		if dir == r || strings.HasPrefix(dir, r+"/") {
			return true
		}
	}
	return false
}

// notStandardLibrary uses Go's convention that a standard library import path
// has no dot in its first element.
func notStandardLibrary(imp string) bool {
	if imp == "C" {
		return false
	}
	first, _, _ := strings.Cut(imp, "/")
	return strings.Contains(first, ".")
}

var packageRules = []struct {
	dirs   []string
	forbid func(imp string) bool
	why    string
}{
	{
		[]string{"internal/resource"},
		notStandardLibrary,
		"internal/resource imports only the standard library",
	},
	{
		[]string{"internal/surface"},
		hasPrefix(module + "/internal/backend"),
		"surfaces reach backends only through internal/cloud",
	},
	{
		[]string{"internal/cloud"},
		func(imp string) bool {
			return hasPrefix("net/http")(imp) ||
				hasPrefix(module+"/internal/sigv4", module+"/internal/surface")(imp)
		},
		"the kernel takes and returns resource types, never HTTP, a signature, or a surface",
	},
}

var ownerRules = []struct {
	match  func(imp string) bool
	owners []string
	why    string
}{
	{
		hasPrefix(
			"google.golang.org/grpc",
			"google.golang.org/protobuf",
			"google.golang.org/genproto",
			vwsProto,
			"cloud.google.com/go/longrunning",
		),
		[]string{"internal/backend/grpcclient"},
		"protobuf and gRPC types stay inside internal/backend/grpcclient",
	},
}

func constrainedDirs() []string {
	var dirs []string
	for _, r := range packageRules {
		dirs = append(dirs, r.dirs...)
	}
	for _, r := range ownerRules {
		dirs = append(dirs, r.owners...)
	}
	return dirs
}

func archViolations(pkgs map[string][]*ast.File) []string {
	var bad []string
	for dir, files := range pkgs {
		for _, f := range files {
			for _, spec := range f.Imports {
				imp, _ := strconv.Unquote(spec.Path.Value)
				for _, r := range packageRules {
					if under(dir, r.dirs...) && r.forbid(imp) {
						bad = append(bad, fmt.Sprintf("%s imports %s: %s", dir, imp, r.why))
					}
				}
				for _, r := range ownerRules {
					if r.match(imp) && !under(dir, r.owners...) {
						bad = append(bad, fmt.Sprintf("%s imports %s: %s", dir, imp, r.why))
					}
				}
			}
		}
	}
	sort.Strings(bad)
	return bad
}

func loadProduction(t *testing.T, root string) map[string][]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	pkgs := map[string][]*ast.File{}
	err := walkGoFiles(root, func(rel string, data []byte) {
		f, err := parser.ParseFile(fset, rel, data, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.ToSlash(filepath.Dir(rel))
		pkgs[dir] = append(pkgs[dir], f)
	})
	if err != nil {
		t.Fatal(err)
	}
	return pkgs
}

func TestArchitectureRules(t *testing.T) {
	probe := t.TempDir()
	for rel, src := range map[string]string{
		"internal/resource/pure.go":     `package resource; import _ "` + module + `/internal/cloud"`,
		"internal/resource/dep.go":      `package resource; import _ "golang.org/x/crypto/argon2"`,
		"internal/surface/console/s.go": `package console; import _ "` + module + `/internal/backend"`,
		"internal/cloud/wire.go":        `package cloud; import _ "net/http"`,
		"internal/cloud/httptest.go":    `package cloud; import _ "net/http/httptest"`,
		"internal/cloud/signature.go":   `package cloud; import _ "` + module + `/internal/sigv4"`,
		"internal/cloud/surface.go":     `package cloud; import _ "` + module + `/internal/surface/console"`,
		"internal/widget/grpc.go":       `package widget; import _ "google.golang.org/grpc"`,
		"internal/widget/protobuf.go":   `package widget; import _ "google.golang.org/protobuf/proto"`,
		"internal/widget/genproto.go": `package widget; import _ "` +
			`google.golang.org/genproto/googleapis/rpc/errdetails"`,
		"internal/widget/proto.go": `package widget; import _ "` + vwsProto + `/gen/go/vws/common/v1"`,
		"internal/widget/longrunning.go": `package widget; import _ "` +
			`cloud.google.com/go/longrunning/autogen/longrunningpb"`,
		"internal/backend/grpcclient/ok.go":  `package grpcclient; import _ "google.golang.org/grpc"`,
		"internal/surface/ec2query/ok.go":    `package ec2query; import _ "` + module + `/internal/cloud"`,
		"internal/resource/std.go":           `package resource; import _ "fmt"`,
		"internal/cloud/backend.go":          `package cloud; import _ "` + module + `/internal/backend"`,
		"internal/surface/s3rest/surface.go": `package s3rest; import _ "` + module + `/internal/sigv4"`,
	} {
		writeFile(t, filepath.Join(probe, rel), src)
	}
	want := []string{
		"internal/cloud imports net/http: the kernel takes and returns resource types, " +
			"never HTTP, a signature, or a surface",
		"internal/cloud imports net/http/httptest: the kernel takes and returns resource types, " +
			"never HTTP, a signature, or a surface",
		"internal/cloud imports " + module + "/internal/sigv4: " +
			"the kernel takes and returns resource types, never HTTP, a signature, or a surface",
		"internal/cloud imports " + module + "/internal/surface/console: " +
			"the kernel takes and returns resource types, never HTTP, a signature, or a surface",
		"internal/resource imports " + module + "/internal/cloud: " +
			"internal/resource imports only the standard library",
		"internal/resource imports golang.org/x/crypto/argon2: " +
			"internal/resource imports only the standard library",
		"internal/surface/console imports " + module + "/internal/backend: " +
			"surfaces reach backends only through internal/cloud",
		"internal/widget imports cloud.google.com/go/longrunning/autogen/longrunningpb: " +
			"protobuf and gRPC types stay inside internal/backend/grpcclient",
		"internal/widget imports " + vwsProto + "/gen/go/vws/common/v1: " +
			"protobuf and gRPC types stay inside internal/backend/grpcclient",
		"internal/widget imports google.golang.org/genproto/googleapis/rpc/errdetails: " +
			"protobuf and gRPC types stay inside internal/backend/grpcclient",
		"internal/widget imports google.golang.org/grpc: " +
			"protobuf and gRPC types stay inside internal/backend/grpcclient",
		"internal/widget imports google.golang.org/protobuf/proto: " +
			"protobuf and gRPC types stay inside internal/backend/grpcclient",
	}
	sort.Strings(want)
	if got := archViolations(loadProduction(t, probe)); !reflect.DeepEqual(got, want) {
		t.Fatalf("probe violations:\n got %q\nwant %q", got, want)
	}

	root := repoRoot(t)
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	moduleLine := ""
	for _, line := range strings.Split(string(mod), "\n") {
		if rest, ok := strings.CutPrefix(line, "module "); ok {
			moduleLine = rest
			break
		}
	}
	if fields := strings.Fields(moduleLine); len(fields) == 0 || fields[0] != module {
		t.Fatalf("go.mod module is not %s; update the module const", module)
	}
	if !strings.Contains(string(mod), vwsProto+" ") {
		t.Fatalf("go.mod does not require %s; update the vwsProto const", vwsProto)
	}
	for _, dir := range constrainedDirs() {
		info, err := os.Stat(filepath.Join(root, dir))
		if err != nil {
			t.Errorf("rule directory %s: %v", dir, err)
		} else if !info.IsDir() {
			t.Errorf("rule directory %s is not a directory", dir)
		}
	}
	for _, v := range archViolations(loadProduction(t, root)) {
		t.Error(v)
	}
}

func walkGoFiles(root string, visit func(rel string, data []byte)) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "third_party" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		visit(rel, data)
		return nil
	})
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
