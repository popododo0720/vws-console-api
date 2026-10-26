package hygiene

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The only file that may build a non-zero iam.AuthorizedPrincipal or touch its
// field: iam.Authorize, after an allowed decision (#342, #517 class 5).
const (
	principalPkgDir = "internal/iam"
	principalHome   = "internal/iam/authorized.go"
	principalType   = "AuthorizedPrincipal"
	principalField  = "arn"
)

// TestOnlyTheAuthorizerBuildsAnAuthorizedPrincipal fails when any Go file,
// tests included, can forge an iam.AuthorizedPrincipal other than through
// iam.Authorize.
//
// Outside package iam the field is unexported, so the compiler rejects every
// literal with a field and every field write; the only way left is unsafe, and
// no file may import it. Inside package iam the package is type-checked, so a
// forgery is found by what it resolves to, not by how it is spelled: a type
// alias or a defined type over AuthorizedPrincipal, a generic type parameter
// constrained to it, an embedded field, a write to the field after a zero
// declaration, or a struct type that declares the same field. The zero literal
// is allowed, since every bound Admin call refuses it.
func TestOnlyTheAuthorizerBuildsAnAuthorizedPrincipal(t *testing.T) {
	root := filepath.Join("..", "..")
	var failures []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		failures = append(failures, principalSyntaxForgeries(filepath.ToSlash(rel), src)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	failures = append(failures, principalPackageForgeries(t, root)...)
	if len(failures) > 0 {
		t.Fatalf("iam.%s forged outside iam.Authorize:\n%s", principalType, strings.Join(failures, "\n"))
	}
}

// principalPackageForgeries type-checks package iam (its in-package tests
// included) from source and lists its forgeries.
func principalPackageForgeries(t *testing.T, root string) []string {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(principalPkgDir))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	srcs := map[string][]byte{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".go" {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		srcs[principalPkgDir+"/"+e.Name()] = src
	}
	fset := token.NewFileSet()
	files, err := parsePackage(fset, srcs, "iam")
	if err != nil {
		t.Fatal(err)
	}
	return principalTypedForgeries(fset, files, importer.ForCompiler(fset, "source", nil))
}

// parsePackage parses the sources that belong to package name; an external
// test package (name_test) cannot reach the unexported field.
func parsePackage(fset *token.FileSet, srcs map[string][]byte, name string) ([]*ast.File, error) {
	rels := make([]string, 0, len(srcs))
	for rel := range srcs {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	var files []*ast.File
	for _, rel := range rels {
		f, err := parser.ParseFile(fset, rel, srcs[rel], parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		if f.Name.Name == name {
			files = append(files, f)
		}
	}
	return files, nil
}

// principalTypedForgeries type-checks files as package iam and lists every
// place outside principalHome that builds or writes an AuthorizedPrincipal:
//   - a composite literal with an element whose type is, or has the core type
//     of, AuthorizedPrincipal's struct (alias, defined type, type parameter);
//   - a conversion to AuthorizedPrincipal or *AuthorizedPrincipal;
//   - any use of its field (a keyed literal, a selector, a write, an address);
//   - a struct type that declares a field of the same name, whose values
//     convert to AuthorizedPrincipal or satisfy a constraint built on it.
//
// A package that does not declare AuthorizedPrincipal, or fails to
// type-check, is itself a finding: the guard must never pass vacuously.
func principalTypedForgeries(fset *token.FileSet, files []*ast.File, imp types.Importer) []string {
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{},
		Defs:  map[*ast.Ident]types.Object{},
		Uses:  map[*ast.Ident]types.Object{},
	}
	var typeErrs []string
	conf := types.Config{Importer: imp, Error: func(err error) { typeErrs = append(typeErrs, err.Error()) }}
	pkg, _ := conf.Check("github.com/popododo0720/vws-console-api/"+principalPkgDir, fset, files, info)
	if len(typeErrs) > 0 {
		return append([]string{principalPkgDir + ": does not type-check"}, typeErrs...)
	}
	obj, _ := pkg.Scope().Lookup(principalType).(*types.TypeName)
	if obj == nil {
		return []string{principalPkgDir + ": " + principalType + " is not declared"}
	}
	named, _ := obj.Type().(*types.Named)
	st, _ := obj.Type().Underlying().(*types.Struct)
	if named == nil || st == nil || st.NumFields() != 1 || st.Field(0).Name() != principalField || st.Field(0).Exported() {
		return []string{fmt.Sprintf("%s: %s must be a struct with the single unexported field %s",
			principalHome, principalType, principalField)}
	}
	field := st.Field(0)
	isPrincipal := func(t types.Type) bool { return principalCore(t, st) }
	var out []string
	report := func(n ast.Node, msg string) {
		pos := fset.Position(n.Pos())
		if filepath.ToSlash(pos.Filename) == principalHome {
			return
		}
		out = append(out, pos.String()+": "+msg)
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				if tv, ok := info.Types[n]; ok && len(n.Elts) > 0 && isPrincipal(tv.Type) {
					report(n, principalType+" literal with a field")
				}
			case *ast.CallExpr:
				tv, ok := info.Types[n.Fun]
				if !ok || !tv.IsType() {
					return true
				}
				target := types.Unalias(tv.Type)
				if p, ok := target.(*types.Pointer); ok {
					target = p.Elem()
				}
				if isPrincipal(target) {
					report(n, "conversion to "+principalType)
				}
			case *ast.Ident:
				if info.Uses[n] == field {
					report(n, principalType+" field "+principalField+" used")
				}
				if v, ok := info.Defs[n].(*types.Var); ok && v.IsField() && v != field && v.Name() == principalField {
					report(n, "struct field "+principalField+" declared beside "+principalType)
				}
			}
			return true
		})
	}
	return out
}

// principalCore reports whether t, after aliases, has st as its underlying
// type, or is a type parameter whose constraint admits a type that does.
func principalCore(t types.Type, st *types.Struct) bool {
	t = types.Unalias(t)
	if tp, ok := t.(*types.TypeParam); ok {
		return constraintAdmits(tp.Constraint(), st, map[types.Type]bool{})
	}
	return types.Identical(t.Underlying(), st)
}

func constraintAdmits(t types.Type, st *types.Struct, seen map[types.Type]bool) bool {
	if seen[t] {
		return false
	}
	seen[t] = true
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Interface:
		for i := range u.NumEmbeddeds() {
			if constraintAdmits(u.EmbeddedType(i), st, seen) {
				return true
			}
		}
	case *types.Union:
		for i := range u.Len() {
			if constraintAdmits(u.Term(i).Type(), st, seen) {
				return true
			}
		}
	default:
		return principalCore(t, st)
	}
	return false
}

// principalSyntaxForgeries lists, in any file, a literal with a field of or
// a conversion to a type spelled AuthorizedPrincipal outside principalHome,
// and any import of unsafe, which could write the unexported field from any
// package.
func principalSyntaxForgeries(rel string, src []byte) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{rel + ": " + err.Error()}
	}
	var out []string
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == "unsafe" {
			out = append(out, fset.Position(imp.Pos()).String()+": imports unsafe")
		}
	}
	if rel == principalHome {
		return out
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			if spelledPrincipal(n.Type) && len(n.Elts) > 0 {
				out = append(out, fset.Position(n.Pos()).String()+": "+principalType+" literal with a field")
			}
		case *ast.CallExpr:
			if spelledPrincipal(n.Fun) {
				out = append(out, fset.Position(n.Pos()).String()+": conversion to "+principalType)
			}
		}
		return true
	})
	return out
}

func spelledPrincipal(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name == principalType
	case *ast.SelectorExpr:
		return e.Sel.Name == principalType
	case *ast.ParenExpr:
		return spelledPrincipal(e.X)
	case *ast.StarExpr:
		return spelledPrincipal(e.X)
	}
	return false
}

// principalHomeFixture stands in for internal/iam/authorized.go in the guard's
// own tests, so the fixtures type-check without imports.
const principalHomeFixture = `package iam

type AuthorizedPrincipal struct{ arn string }

func (a AuthorizedPrincipal) String() string { return a.arn }

func Authorize(arn string) AuthorizedPrincipal { return AuthorizedPrincipal{arn: arn} }
`

// The guard inside package iam, on the forgeries of #355's Codex review
// (vws-console-api-355-0950255.md, P2: aliases and field assignments) and
// their relatives. Each forgery is a finding; the allowed uses are not.
func TestAuthorizedPrincipalTypedGuard(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      int
	}{
		// Allowed.
		{"zero literal", "var _ = AuthorizedPrincipal{}", 0},
		{"zero declaration", "var z AuthorizedPrincipal\nvar _ = z.String()", 0},
		{"through Authorize", "var _ = Authorize(\"arn:vws:iam::1:user/a\")", 0},
		{"zero alias literal", "type binding = AuthorizedPrincipal\nvar _ = binding{}", 0},
		{"copy of a binding", "func f(a AuthorizedPrincipal) AuthorizedPrincipal { b := a; return b }", 0},
		{"other struct", "type ref struct{ ARN string }\nvar _ = ref{ARN: \"a\"}", 0},
		// Codex #355 P2: a type alias.
		{"alias keyed", "type binding = AuthorizedPrincipal\nvar forged = binding{arn: \"unchecked\"}", 2},
		{"alias positional", "type binding = AuthorizedPrincipal\nvar forged = binding{\"unchecked\"}", 1},
		// Codex #355 P2: a field write after a zero declaration.
		{"field write", "func f() AuthorizedPrincipal { var z AuthorizedPrincipal; z.arn = \"unchecked\"; return z }", 1},
		{"field write through alias", "type b = AuthorizedPrincipal\nfunc f() b { var z b; z.arn = \"x\"; return z }", 1},
		{"field address", "func f() AuthorizedPrincipal { var z AuthorizedPrincipal; p := &z.arn; *p = \"x\"; return z }", 1},
		{"field write through pointer", "func f(p *AuthorizedPrincipal) { p.arn = \"x\" }", 1},
		{"field read outside home", "func f(a AuthorizedPrincipal) string { return a.arn }", 1},
		// Relatives.
		{"plain keyed", "var _ = AuthorizedPrincipal{arn: \"a\"}", 2},
		{"defined type positional", "type b AuthorizedPrincipal\nvar _ = AuthorizedPrincipal(b{\"a\"})", 2},
		{"anonymous struct conversion", "var _ = AuthorizedPrincipal(struct{ arn string }{\"a\"})", 3},
		{"pointer conversion", "type raw struct{ arn string }\n" +
			"func f(r *raw) *AuthorizedPrincipal { return (*AuthorizedPrincipal)(r) }", 2},
		{"embedded field write", "type w struct{ AuthorizedPrincipal }\n" +
			"func f() AuthorizedPrincipal { var x w; x.arn = \"a\"; return x.AuthorizedPrincipal }", 1},
		{"type parameter literal", "func f[T interface{ AuthorizedPrincipal }]() T { return T{\"a\"} }\n" +
			"var _ = f[AuthorizedPrincipal]()", 1},
		{"approximate constraint", "type c interface{ ~struct{ arn string } }\nfunc f[T c]() T { return T{arn: \"a\"} }", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := typedFixture(t, map[string]string{"internal/iam/x.go": "package iam\n\n" + tc.src + "\n"})
			if len(got) != tc.want {
				t.Errorf("%q: %d findings %v, want %d", tc.src, len(got), got, tc.want)
			}
		})
	}
}

// The typed guard never passes vacuously, and it reads in-package test files
// but not an external test package.
func TestAuthorizedPrincipalTypedGuardScope(t *testing.T) {
	fset := token.NewFileSet()
	files, err := parsePackage(fset, map[string][]byte{"internal/iam/x.go": []byte("package iam\n")}, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if got := principalTypedForgeries(fset, files, nil); len(got) != 1 || !strings.Contains(got[0], "is not declared") {
		t.Errorf("package without %s: %v, want not declared", principalType, got)
	}
	exported := strings.ReplaceAll(principalHomeFixture, "arn", "ARN")
	for _, tc := range []struct {
		name, rel, src, want string
		n                    int
	}{
		{"does not type-check", "internal/iam/x.go", "package iam\nvar _ = undefinedName\n", "does not type-check", -1},
		{
			"in-package test forgery", "internal/iam/x_test.go",
			"package iam\nvar _ = AuthorizedPrincipal{arn: \"a\"}\n", "", 2,
		},
		{"external test package", "internal/iam/x_test.go", "package iam_test\nvar _ = 1\n", "", 0},
		{"exported field", principalHome, exported, "single unexported field", -1},
	} {
		got := typedFixture(t, map[string]string{tc.rel: tc.src})
		switch {
		case tc.n >= 0 && len(got) != tc.n:
			t.Errorf("%s: %v, want %d findings", tc.name, got, tc.n)
		case tc.n < 0 && (len(got) == 0 || !strings.Contains(got[0], tc.want)):
			t.Errorf("%s: %v, want a finding %q", tc.name, got, tc.want)
		}
	}
}

func typedFixture(t *testing.T, extra map[string]string) []string {
	t.Helper()
	srcs := map[string][]byte{principalHome: []byte(principalHomeFixture)}
	for rel, src := range extra {
		srcs[rel] = []byte(src)
	}
	fset := token.NewFileSet()
	files, err := parsePackage(fset, srcs, "iam")
	if err != nil {
		t.Fatal(err)
	}
	return principalTypedForgeries(fset, files, nil)
}

// The repository-wide syntax guard: a forged literal or conversion anywhere
// but the authorizer is reported, and so is any import of unsafe; the zero
// literal and Authorize's own literal are not.
func TestAuthorizedPrincipalSyntaxGuard(t *testing.T) {
	for _, tc := range []struct {
		rel, src string
		want     int
	}{
		{"internal/surface/iamquery/x.go", "package x\nvar _ = iam.AuthorizedPrincipal{}\n", 0},
		{"internal/surface/iamquery/x.go", "package x\nvar a iam.AuthorizedPrincipal\n", 0},
		{"internal/iam/x.go", "package iam\nvar _ = AuthorizedPrincipal{arn: \"arn:vws:iam::1:user/a\"}\n", 1},
		{"internal/iam/x_test.go", "package iam\nvar _ = AuthorizedPrincipal{\"arn\"}\n", 1},
		{"internal/iam/x.go", "package iam\nvar _ = AuthorizedPrincipal(struct{ arn string }{\"a\"})\n", 1},
		{"internal/backend/x.go", "package x\nvar _ = (iam.AuthorizedPrincipal)(v)\n", 1},
		{"internal/backend/x.go", "package x\nvar _ = (*iam.AuthorizedPrincipal)(p)\n", 1},
		{"internal/backend/x.go", "package x\nimport \"unsafe\"\nvar _ = unsafe.Sizeof(0)\n", 1},
		{"internal/backend/x.go", "package x\nimport u \"unsafe\"\nvar _ = u.Sizeof(0)\n", 1},
		{principalHome, "package iam\nvar _ = AuthorizedPrincipal{arn: arn}\n", 0},
		{principalHome, "package iam\nimport \"unsafe\"\n", 1},
	} {
		if got := principalSyntaxForgeries(tc.rel, []byte(tc.src)); len(got) != tc.want {
			t.Errorf("%s %q: %v, want %d findings", tc.rel, tc.src, got, tc.want)
		}
	}
}
