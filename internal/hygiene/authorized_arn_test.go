package hygiene

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// authorizedARNHome is the only file that may build a non-zero
// iam.AuthorizedARN: iam.Authorize, after an allowed decision (#342).
const authorizedARNHome = "internal/iam/authorized.go"

// TestOnlyTheAuthorizerBuildsAnAuthorizedARN fails when any Go file, tests
// included, builds an iam.AuthorizedARN other than through iam.Authorize: a
// composite literal with a field, or a conversion. The zero literal is
// allowed, since every bound Admin call refuses it.
func TestOnlyTheAuthorizerBuildsAnAuthorizedARN(t *testing.T) {
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
		failures = append(failures, authorizedARNBuilds(filepath.ToSlash(rel), src)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) > 0 {
		t.Fatalf("iam.AuthorizedARN built outside iam.Authorize:\n%s", strings.Join(failures, "\n"))
	}
}

// authorizedARNBuilds lists the places src builds an AuthorizedARN that
// only iam.Authorize may build.
func authorizedARNBuilds(rel string, src []byte) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{rel + ": " + err.Error()}
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			if isAuthorizedARN(n.Type) && len(n.Elts) > 0 && rel != authorizedARNHome {
				out = append(out, fset.Position(n.Pos()).String()+": AuthorizedARN literal with a field")
			}
		case *ast.CallExpr:
			if isAuthorizedARN(n.Fun) {
				out = append(out, fset.Position(n.Pos()).String()+": conversion to AuthorizedARN")
			}
		}
		return true
	})
	return out
}

func isAuthorizedARN(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name == "AuthorizedARN"
	case *ast.SelectorExpr:
		return e.Sel.Name == "AuthorizedARN"
	case *ast.ParenExpr:
		return isAuthorizedARN(e.X)
	}
	return false
}

// The guard itself: a forged literal or conversion anywhere but the
// authorizer is reported; the zero literal and Authorize's own literal are
// not.
func TestAuthorizedARNBuildsGuard(t *testing.T) {
	for _, tc := range []struct {
		rel, src string
		want     int
	}{
		{"internal/surface/iamquery/x.go", "package x\nvar _ = iam.AuthorizedARN{}\n", 0},
		{"internal/surface/iamquery/x.go", "package x\nvar a iam.AuthorizedARN\n", 0},
		{"internal/iam/x.go", "package iam\nvar _ = AuthorizedARN{arn: \"arn:vws:iam::1:user/a\"}\n", 1},
		{"internal/iam/x_test.go", "package iam\nvar _ = AuthorizedARN{\"arn\"}\n", 1},
		{"internal/iam/x.go", "package iam\nvar _ = AuthorizedARN(struct{ arn string }{\"a\"})\n", 1},
		{"internal/backend/x.go", "package x\nvar _ = (iam.AuthorizedARN)(v)\n", 1},
		{authorizedARNHome, "package iam\nvar _ = AuthorizedARN{arn: arn}\n", 0},
	} {
		if got := authorizedARNBuilds(tc.rel, []byte(tc.src)); len(got) != tc.want {
			t.Errorf("%s %q: %v, want %d findings", tc.rel, tc.src, got, tc.want)
		}
	}
}
