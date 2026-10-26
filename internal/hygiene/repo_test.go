package hygiene

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
	gomodule "golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

func TestRepositoryRules(t *testing.T) {
	root := filepath.Join("..", "..")
	var failures []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "helm", "k8s", "deploy":
				if d.Name() != ".git" {
					failures = append(failures, "deployment directory "+rel)
				}
				return filepath.SkipDir
			}
			if rel == "proto" {
				failures = append(failures, "local proto tree "+rel)
				return filepath.SkipDir
			}
			if filepath.ToSlash(rel) == "third_party/vws-proto" {
				failures = append(failures, "vendored vws-proto copy "+rel+"; require a vws-proto tag in go.mod instead")
				return filepath.SkipDir
			}
			return nil
		}
		if strings.Contains(filepath.ToSlash(rel), "grpcclient/internal/pb") || strings.HasSuffix(d.Name(), ".pb.go") {
			failures = append(failures, "generated protobuf in "+rel)
		}
		base := d.Name()
		switch base {
		case "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Chart.yaml":
			failures = append(failures, "deployment file "+rel)
		}
		ext := strings.ToLower(filepath.Ext(base))
		switch ext {
		case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp":
			failures = append(failures, "image file "+rel)
		}
		if ext == ".go" && !strings.HasSuffix(base, "_test.go") && !strings.HasPrefix(filepath.ToSlash(rel), "internal/backend/") {
			if msg := mintCall(path); msg != "" {
				failures = append(failures, rel+": "+msg)
			}
		}
		if isText(ext, base) && base != "LICENSE" && !strings.HasSuffix(base, ".pb.go") {
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			low := strings.ToLower(string(body))
			if strings.Contains(low, brandPhrase()) || strings.Contains(low, vendorHost()) {
				failures = append(failures, "branding text in "+rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	failures = append(failures, protoModuleRules(string(mod))...)
	if len(failures) > 0 {
		t.Fatalf("repository rules:\n%s", strings.Join(failures, "\n"))
	}
}

// protoModulePath is the resource API module. It is consumed from a release tag through the module proxy.
const protoModulePath = "github.com/popododo0720/vws-proto"

// protoModuleRules returns the go.mod problems for the resource API module: a replace of it, a require
// that is not a release tag, or no require at all. Only the require and replace directives count, so an
// exclude or retract line naming a tag does not satisfy the rule.
func protoModuleRules(mod string) []string {
	f, err := modfile.Parse("go.mod", []byte(mod), nil)
	if err != nil {
		return []string{"go.mod does not parse: " + err.Error()}
	}
	var failures []string
	for _, r := range f.Replace {
		if r.Old.Path == protoModulePath {
			failures = append(failures, "go.mod replaces "+protoModulePath+" with "+r.New.String()+
				"; require a release tag instead")
		}
	}
	tagged := false
	for _, r := range f.Require {
		if r.Mod.Path != protoModulePath {
			continue
		}
		if !isReleaseTag(r.Mod.Version) {
			failures = append(failures, "go.mod requires "+r.Mod.String()+"; require a release tag vX.Y.Z instead")
			continue
		}
		tagged = true
	}
	if !tagged {
		failures = append(failures, "go.mod does not require "+protoModulePath+" at a release tag vX.Y.Z")
	}
	return failures
}

// isReleaseTag reports whether v is a release tag such as v0.5.0: canonical semver with no pre-release or
// build suffix, not a pseudo-version, and not the v0.0.0 placeholder.
func isReleaseTag(v string) bool {
	return semver.IsValid(v) && semver.Canonical(v) == v && semver.Prerelease(v) == "" &&
		!gomodule.IsPseudoVersion(v) && v != "v0.0.0"
}

func brandPhrase() string { return "Amazon Web " + "Services" }

func vendorHost() string { return "amazon" + "aws" }

func isText(ext, base string) bool {
	switch ext {
	case ".go", ".md", ".yml", ".yaml", ".proto", ".mod":
		return true
	}
	return base == "buf.yaml" || base == "buf.gen.yaml"
}

func mintCall(path string) string {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return err.Error()
	}
	var hit string
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != "resource" {
			return true
		}
		if sel.Sel.Name == "Mint" || sel.Sel.Name == "NewOperationID" {
			hit = sel.Sel.Name + " is only for backends"
		}
		return true
	})
	return hit
}

func TestProtoModuleRules(t *testing.T) {
	const tagged = "require github.com/popododo0720/vws-proto v0.5.0\n"
	cases := []struct {
		name string
		mod  string
		bad  bool
	}{
		{"tag in a require block", "require (\n\tgithub.com/popododo0720/vws-proto v0.5.0\n)\n", false},
		{"single-line require", tagged, false},
		{"tag with indirect comment", "require (\n\tgithub.com/popododo0720/vws-proto v0.5.0 // indirect\n)\n", false},
		{"replace to a local copy", tagged + "replace github.com/popododo0720/vws-proto => ./third_party/vws-proto\n", true},
		{"replace in a block", tagged + "replace (\n\tgithub.com/popododo0720/vws-proto => ../vws-proto\n)\n", true},
		{"pseudo-version", "require github.com/popododo0720/vws-proto v0.4.1-0.20261021123535-8f0a84ed9918\n", true},
		{"placeholder version", "require github.com/popododo0720/vws-proto v0.0.0-00010101000000-000000000000\n", true},
		{"pre-release", "require github.com/popododo0720/vws-proto v0.6.0-rc.1\n", true},
		{"missing", "require google.golang.org/grpc v1.84.0\n", true},
		{
			"exclude block plus pseudo-version",
			"require github.com/popododo0720/vws-proto v0.4.1-0.20261021123535-8f0a84ed9918\n" +
				"exclude (\n\tgithub.com/popododo0720/vws-proto v0.5.0\n)\n", true,
		},
		{"v0.0.0 placeholder", "require github.com/popododo0720/vws-proto v0.0.0\n", true},
		{"not semver", "require github.com/popododo0720/vws-proto latest\n", true},
		{
			"replace of one version",
			tagged + "replace github.com/popododo0720/vws-proto v0.5.0 => example.com/fork v0.5.0\n", true,
		},
		{
			"valid tag in a full go.mod",
			"module example.com/x\n\ngo 1.26.0\n\nrequire (\n\tgithub.com/popododo0720/vws-proto v0.5.0\n" +
				"\tgoogle.golang.org/grpc v1.84.0\n)\n\nexclude github.com/popododo0720/vws-proto v0.4.0\n", false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := protoModuleRules(tc.mod)
			if (len(got) > 0) != tc.bad {
				t.Fatalf("protoModuleRules(%q) = %q, want failure %v", tc.mod, got, tc.bad)
			}
		})
	}
}
